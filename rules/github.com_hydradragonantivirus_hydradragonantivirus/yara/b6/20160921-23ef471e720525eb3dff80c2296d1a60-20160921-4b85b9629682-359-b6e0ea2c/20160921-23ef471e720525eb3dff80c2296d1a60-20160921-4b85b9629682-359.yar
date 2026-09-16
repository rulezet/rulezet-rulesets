rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_4b85b9629682_359 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash3       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"

  strings:
    $s1  = "Bs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s2  = "unction f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s3  = "on f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return " ascii
    $s4  = "eturn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})()" ascii
    $s5  = "\"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(functio" ascii
    $s6  = "),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s7  = "n f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TR" ascii
    $s8  = "urn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(f" ascii
    $s9  = " f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s10 = "on f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s11 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";" ascii
    $s12 = "ion f000(){return \"UEg\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s13 = "n f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"X" ascii
    $s14 = "000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XT" ascii
    $s15 = " f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp" ascii
    $s16 = "){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})" ascii
    $s17 = " \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s18 = " f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"U" ascii
    $s19 = "\"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s20 = " f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"D" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}