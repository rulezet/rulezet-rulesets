rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_63def3fff7f1_5187 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash3       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash4       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(" ascii
    $s2 = "unction f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){retu" ascii
    $s3 = ")(),(function f000(){return \"PTi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(" ascii
    $s4 = "000(){return \"Wy\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\"" ascii
    $s5 = "rn \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}