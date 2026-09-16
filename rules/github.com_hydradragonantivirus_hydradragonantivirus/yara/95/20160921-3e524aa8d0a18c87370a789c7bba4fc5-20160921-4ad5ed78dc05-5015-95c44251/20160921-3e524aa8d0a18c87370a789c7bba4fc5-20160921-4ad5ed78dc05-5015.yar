rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_4ad5ed78dc05_5015 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"

  strings:
    $s1 = "(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s2 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){retur" ascii
    $s3 = "turn \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})()," ascii
    $s4 = "unction f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){ret" ascii
    $s5 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}