rule _20160921_6b34f0b83cb5d89ac574db511a389f02_20160921_c10352a0b5ce_1734 {
  meta:
    description = "datamaliciousorder - from files 20160921_6b34f0b83cb5d89ac574db511a389f02.js, 20160921_c10352a0b5ce476f023184a502920234.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"
    hash3       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"

  strings:
    $s1  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Nv\";})(" ascii
    $s2  = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return" ascii
    $s3  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s4  = ";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s5  = "0(){return \"Yv\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";" ascii
    $s6  = "eturn \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()," ascii
    $s7  = "ction f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s8  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function f" ascii
    $s9  = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KDh" ascii
    $s10 = "function f000(){return \"Vj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){ret" ascii
    $s11 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Qa" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}