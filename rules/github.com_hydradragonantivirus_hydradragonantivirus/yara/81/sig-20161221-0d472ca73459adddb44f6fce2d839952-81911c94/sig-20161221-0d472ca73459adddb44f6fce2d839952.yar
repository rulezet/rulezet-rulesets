rule sig_20161221_0d472ca73459adddb44f6fce2d839952 {
  meta:
    description = "datamaliciousorder - file 20161221_0d472ca73459adddb44f6fce2d839952.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "323b1b9cd967ab48c0076790e2d2121fcbf85f3a583aa72c96bc64df01e55b7c"

  strings:
    $s1 = "var ynlaraviw2 = new Function(uvave[5] + kxisipte[12] + wela[5] + vronyzwa[7] + [34, \"ct\", 26, 94, 2, 87, 24, 55, 73, 74, 51, " ascii
    $s2 = "var ynlaraviw2 = new Function(uvave[5] + kxisipte[12] + wela[5] + vronyzwa[7] + [34, \"ct\", 26, 94, 2, 87, 24, 55, 73, 74, 51, " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}