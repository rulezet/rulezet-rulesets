rule sig_20161222_baceea808c89d81bdca861ae8de0569f {
  meta:
    description = "datamaliciousorder - file 20161222_baceea808c89d81bdca861ae8de0569f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dc0edbc533fd9f88162077dc45ba8bb14625b0a018628e17bd1ec2fd1148973"

  strings:
    $s1 = "if (['jr', 'cr', 'p', 'u', 'k', 'y', 'q', 'e', 'b', 'cq', 'vn', 'l', 'u', 'u', 'q', new Function(['y', wsokjimf, 'c', 'n', 'lq'," ascii
    $s2 = "awxaro3 = [this][0][['sq', 'y', 'mf', 'n', 'o', 'x', hzaro, 'lx', 'hm', 'vt', 'l', 'w', 'y', 'gl', 'a', 'qx', 'o', 'v', 'e', 'm'" ascii
    $s3 = ", 'a', cute, 'y', 'z', 'e', 'y', 'kr', 'o', 'i', 'e', 'e', 'b', 'e', 'i', 'i', 'v', 'tk', 'u', 'a', 'b', 'n', 'u'][5] + ['y', ba" ascii
    $s4 = "var cute = [\"yp\"][0];" fullword ascii
    $s5 = "if (['jr', 'cr', 'p', 'u', 'k', 'y', 'q', 'e', 'b', 'cq', 'vn', 'l', 'u', 'u', 'q', new Function(['y', wsokjimf, 'c', 'n', 'lq'," ascii
    $s6 = "awxaro3 = [this][0][['sq', 'y', 'mf', 'n', 'o', 'x', hzaro, 'lx', 'hm', 'vt', 'l', 'w', 'y', 'gl', 'a', 'qx', 'o', 'v', 'e', 'm'" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}