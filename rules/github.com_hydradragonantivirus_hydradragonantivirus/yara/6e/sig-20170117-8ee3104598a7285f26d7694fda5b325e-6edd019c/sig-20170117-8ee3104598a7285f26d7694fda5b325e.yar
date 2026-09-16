rule sig_20170117_8ee3104598a7285f26d7694fda5b325e {
  meta:
    description = "datamaliciousorder - file 20170117_8ee3104598a7285f26d7694fda5b325e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be7b6a5112f7fef0632eb87b5d9a4832b3743b32e13fdff252ae83a40437ec8d"

  strings:
    $s1 = "var igygyjsexl08 = new Function(ogelxazijwutceqojibvadrebyxcamverusakosatypyvitavahzarxubyrkirgovorylyganaduwe[1] + iwsepwasirty" ascii
    $s2 = "var igygyjsexl08 = new Function(ogelxazijwutceqojibvadrebyxcamverusakosatypyvitavahzarxubyrkirgovorylyganaduwe[1] + iwsepwasirty" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}