rule RUSSIANPANDA_Solarmarker_First_Stage_Payload: FILE {
  meta:
    description = "Detects SolarMarker First Stage payload"
    author      = "RussianPanda"
    id          = "56eec644-9ad7-51db-9d11-68ea3e12c36a"
    date        = "2024-01-30"
    modified    = "2024-01-30"
    reference   = "https://x.com/luke92881/status/1751968350689771966?s=20"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/SolarMarker/solarmarker_first_stage_payload.yar#L1-L21"
    license_url = "N/A"
    hash        = "f53563541293a826738d3b8f1164ea43"
    logic_hash  = "e704614782b0f3cba60c53413e889113d2d44f37e60801205e5ed5ff921b13ee"
    score       = 75
    quality     = 71
    tags        = "FILE"

  strings:
    $s1 = "credui"
    $s2 = "CredUIPromptForCredentials"
    $s3 = "PowerShell"
    $s4 = "set_CursorPosition"
    $s5 = "set_AcceptButton"
    $s6 = "MessageBoxButtons"
    $s7 = "AgileDotNetRT"
    $s8 = "_CorExeMain"

  condition:
    all of them and filesize > 250MB
}