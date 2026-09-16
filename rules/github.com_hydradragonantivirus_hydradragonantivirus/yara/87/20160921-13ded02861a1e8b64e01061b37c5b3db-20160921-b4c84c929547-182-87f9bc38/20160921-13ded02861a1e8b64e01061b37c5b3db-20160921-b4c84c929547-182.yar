rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_b4c84c929547_182 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1  = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(fu" ascii
    $s2  = "eturn \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(" ascii
    $s3  = "(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})" ascii
    $s4  = "return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(" ascii
    $s5  = "turn \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})()" ascii
    $s6  = "),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){" ascii
    $s7  = "0(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";" ascii
    $s8  = "nction f000(){return \"OUx\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s9  = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s10 = ",(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Qz\";})(),(function f000(){re" ascii
    $s11 = "ion f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s12 = "00(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn" ascii
    $s13 = "tion f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s14 = "urn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(f" ascii
    $s15 = "eturn \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s16 = "n f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Y" ascii
    $s17 = "ion f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii
    $s18 = "n \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s19 = "00(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\"" ascii
    $s20 = "n \"Um\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}