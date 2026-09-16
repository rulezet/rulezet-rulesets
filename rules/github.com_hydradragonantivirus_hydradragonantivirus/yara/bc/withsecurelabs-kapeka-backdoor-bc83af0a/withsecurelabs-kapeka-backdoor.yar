import "pe"
rule WITHSECURELABS_Kapeka_Backdoor: FILE {
  meta:
    description = "Detects Kapeka backdoor based on common strings."
    author      = "WithSecure"
    id          = "7b874a4a-a009-5365-9c31-ca61bf5ab491"
    date        = "2024-04-17"
    modified    = "2024-04-17"
    reference   = "https://labs.withsecure.com/publications/kapeka"
    source_url  = "https://github.com/WithSecureLabs/iocs/blob/29adc4b6c2c2850f0f385aec77ab6fc0d7a8f20c/Kapeka/kapeka_backdoor.yar#L2-L21"
    license_url = "https://github.com/WithSecureLabs/iocs/blob/29adc4b6c2c2850f0f385aec77ab6fc0d7a8f20c/LICENSE"
    logic_hash  = "49795c6e3f3690eeccd731a9ba0c6bd8d5840d9171939e71d3a4d6f0d1834f05"
    score       = 75
    quality     = 25
    tags        = "FILE"
    version     = "1.0"
    hash1       = "97e0e161d673925e42cdf04763e7eaa53035338b"
    hash2       = "9bbde40cab30916b42e59208fbcc09affef525c1"
    hash3       = "6c3441b5a4d3d39e9695d176b0e83a2c55fe5b4e"

  strings:
    $a = "Azbi3l1xIgcRzTsOHopgrwUdJUMWpOFt" ascii
    $b = "PID : " wide
    $c = "ExitCode : " wide
    $d = "1: " wide
    $e = "2: " wide

  condition:
    pe.is_dll() and filesize > 50000 and filesize < 500000 and 4 of them
}