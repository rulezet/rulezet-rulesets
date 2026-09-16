rule sig_20160822_68733d033f77d54c186819d9966d1faa {
  meta:
    description = "datamaliciousorder - file 20160822_68733d033f77d54c186819d9966d1faa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "261bef243bb2347c1060da03c3dae05bb37bcd3ae75261ce61be47063b53dcb5"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}