rule _20160921_4855f7b1e1da9c1c5863fa798f27645a_20160921_c1ad71fea9bd_3730 {
  meta:
    description = "datamaliciousorder - from files 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1 = "return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})" ascii
    $s2 = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s3 = "tion f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s4 = "turn \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5 = "on f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s6 = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}