rule sig_20160525_321237731d88bfeb048cd2810898626e {
  meta:
    description = "datamaliciousorder - file 20160525_321237731d88bfeb048cd2810898626e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2356283610b753c633e34af22617e8158a93523066e20d8c8a5c05b32880abdb"

  strings:
    $s1 = "darn rav;\"sch\" = dnenoisillocn rav\\n;\"ec6x\\\\\" = keppeln rav\\n;\"htge6x\\\\\" = ecapsetihwxelfn rav\\n;\"e6x\\\\uR\" = mo" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}