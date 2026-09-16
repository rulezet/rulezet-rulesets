rule _20160921_6f40563df6afd13be332d60057d492bb_20160921_c05dd34a0935_5381 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash2       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash3       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1 = ")(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s2 = "turn \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})()" ascii
    $s3 = "return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})()," ascii
    $s4 = " \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s5 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}