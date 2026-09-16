rule sig_20160822_3f3d59e883e968db7c2fef0a8a10cd99 {
  meta:
    description = "datamaliciousorder - file 20160822_3f3d59e883e968db7c2fef0a8a10cd99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "634d8797c8db9ec45ec2194dbbe51cbb2317f3a0d7ecda75cde19d1708646d4e"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}