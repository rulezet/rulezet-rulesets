rule Whispergate_Stage_1 {
  meta:
    description = "Detects first stage payload from WhisperGate"
    author      = "mmuir@cadosecurity.com"
    date        = "2022-01-17"
    license     = "Apache License 2.0"
    hash        = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
    report      = "https://github.com/cado-security/DFIR_Resources_Whispergate"

  strings:
    $a = "1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv"
    $b = "8BEDC411012A33BA34F49130D0F186993C6A32DAD8976F6A5D82C1ED23054C057ECED5496F65"
    $c = "$10k via bitcoin wallet"
    $d = "tox ID"

  condition:
    uint16(0) == 0x5A4D and all of them
}