import "pe"
rule WITHSECURELABS_SILKLOADER {
  meta:
    description = "Detects SILKLOADER samples"
    author      = "WithSecure"
    id          = "bb8a543e-fdbf-5be1-901e-3e2a9965fd62"
    date        = "2023-03-15"
    modified    = "2023-03-15"
    reference   = "https://labs.withsecure.com/publications/silkloader"
    source_url  = "https://github.com/WithSecureLabs/iocs/blob/29adc4b6c2c2850f0f385aec77ab6fc0d7a8f20c/SILKLOADER/silkloader.yar#L2-L20"
    license_url = "https://github.com/WithSecureLabs/iocs/blob/29adc4b6c2c2850f0f385aec77ab6fc0d7a8f20c/LICENSE"
    logic_hash  = "48aa249ea78e5a3bfe9934fd0dfa26b79f9e6cbe1e5b1426b84f8d8a3d77d742"
    score       = 75
    quality     = 75
    tags        = ""
    version     = "1.0"
    hash1       = "c83ac6dc96febd49c7c558e8cf85dd8bcb3a84fdc78b3ba72ebf681566dc1865"
    hash2       = "e4dadabd1cee7215ff6e31e01f6b0dd820851685836592a14f982f2c7972fc25"
    hash3       = "d77a59e6ba3a8f3c000a8a8955af77d2898f220f7bf3c0968bf0d7c8ac25a5ad"

  strings:
    $str1 = { 54 00 52 00 41 00 4e 00 53 00 46 00 45 00 52 00 }
    $str2 = { 76 00 62 00 63 00 63 00 73 00 62 00 }

  condition:
    uint16(0) == 0x5A4D and pe.characteristics & pe.DLL and all of them
}