rule sig_20160824_e9d8ea46a8e1e863ea88970583ef30aa {
  meta:
    description = "datamaliciousorder - file 20160824_e9d8ea46a8e1e863ea88970583ef30aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "333f268779654455ec2019e9a937161357efee56990859ab108a43dd46ac76d6"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}