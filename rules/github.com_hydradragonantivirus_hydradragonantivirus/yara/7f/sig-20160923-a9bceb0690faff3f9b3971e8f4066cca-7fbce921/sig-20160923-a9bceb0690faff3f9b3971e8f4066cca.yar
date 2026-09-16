rule sig_20160923_a9bceb0690faff3f9b3971e8f4066cca {
  meta:
    description = "datamaliciousorder - file 20160923_a9bceb0690faff3f9b3971e8f4066cca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d65e2d40d125dbcafbc563dd9e08571d6b8cb843d63794900adad6e867b8c3f"

  strings:
    $s1 = "var vxuzepa0 = new Array('vo', WScript, 'ta', 'yme')[1];" fullword ascii
    $s2 = "var qnizkajeny0 = new Function({" fullword ascii
    $s3 = "var pzugji = new Function({" fullword ascii
    $s4 = "dheri: \"peo\"," fullword ascii
    $s5 = "var becri = new Function({" fullword ascii
    $s6 = "surah: 'rzybcij9'," fullword ascii
    $s7 = "} catch (nnirukt2) {}" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    all of them
}