rule ARKBIRD_SOLG_APT_Lazarus_HTA_Apr_2021_1: FILE {
  meta:
    description = "Detect HTA with the fake picture header as decoy used by Lazarus"
    author      = "Arkbird_SOLG"
    id          = "1a57251e-f0fb-541c-bf8b-f1afecf7f1c7"
    date        = "2021-04-27"
    modified    = "2021-04-27"
    reference   = "Internal Research"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-04-27/Lazarus/APT_Lazarus_HTA_Apr_2021_1.yara#L1-L21"
    license_url = "N/A"
    logic_hash  = "40c2e5b662d1999c3ae5be97604bb9ebc809a383d66331cb4b385666ce55be2a"
    score       = 75
    quality     = 63
    tags        = "FILE"
    hash1       = "888cfc87b44024c48eed794cc9d6dea9f6ae0cc3468dee940495e839a12ee0db"
    tlp         = "white"
    adversary   = "Lazarus"

  strings:
    $s1 = "\n<script language=\"javascript\">"
    $s2 = "['OpenTextFile','CreateTextFile'"
    $s3 = "['push']"
    $s4 = "('MZ'),e['Close']()"
    $s5 = "['shift']()"
    $s6 = ";var data=["
    $s7 = "b=new ActiveXObject('Scripting.FileSystemObject')"

  condition:
    (uint16(0) == 0x4d42 or uint16(0) == 0xd8ff or uint32(0) == 0x474e5089 or uint32(0) == 0x38464947) and filesize > 20KB and 5 of ($s*)
}