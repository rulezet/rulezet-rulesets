rule EMBEERESEARCH_Win_Redline_Loader_Dec_2023 {
  meta:
    description = "Patterns observed in redline loader"
    author      = "Matthew @ Embee_Research"
    id          = "59d933a8-8ccd-565f-b379-e0bf6c3d3111"
    date        = "2023-12-24"
    modified    = "2023-12-29"
    reference   = "https://github.com/embee-research/Yara-detection-rules/"
    source_url  = "https://github.com/embee-research/Yara-detection-rules//blob/ac56d6f6fd2a30c8cb6e5c0455d6519210a8b0f4/Rules/win_redline_loader_dec_2023.yar#L1-L20"
    license_url = "N/A"
    hash        = ""
    logic_hash  = "831c32f9998b97f7ceeb14df73a264a998df5f8800aaa5271755aaaeac070010"
    score       = 75
    quality     = 75
    tags        = ""

  strings:
    $s1 = { 8b ?? ?? 0c 30 04 31 46 3b f7 7c ?? 5d 5b 5e 83 ?? ?? 75 }
    $s2 = "WritePrivateProfileStringA"
    $s3 = "SetFileShortNameA"
    $s4 = "- Attempt to use MSIL code from this assembly during native code initialization"

  condition:
    all of them
}