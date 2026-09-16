rule EMBEERESEARCH_Win_Berbew_Strings_Dec_2023 {
  meta:
    description = "Strings observed in Berbew malware."
    author      = "Matthew @ Embee_Research"
    id          = "402711af-c543-5c95-ae9e-e663825b6653"
    date        = "2023-12-24"
    modified    = "2023-12-26"
    reference   = "https://github.com/embee-research/Yara-detection-rules/"
    source_url  = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_berbew_strings_dec_2023.yar#L1-L19"
    license_url = "N/A"
    hash        = "24dc0af3c51118697df999d8bffcdfc9cbf0d07f2630473450dd826a1ae4b9ae"
    logic_hash  = "a7f687e749ec69961777063d52678461a8e288c80037fac051d7b1a5b568d9e8"
    score       = 75
    quality     = 75
    tags        = ""

  strings:
    $s1 = "This KEWL STUFF was coded by V. V. PUPKIN"
    $s2 = "REAL CASH, REAL BITCHEZ"
    $s3 = "Please, enter your Card Number"

  condition:
    all of them
}