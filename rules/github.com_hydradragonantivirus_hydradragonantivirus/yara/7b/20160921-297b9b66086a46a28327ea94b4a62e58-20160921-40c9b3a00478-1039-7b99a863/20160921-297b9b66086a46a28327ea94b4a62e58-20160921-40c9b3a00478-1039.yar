rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_40c9b3a00478_1039 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash3       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"

  strings:
    $s1  = "on f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"R" ascii
    $s2  = "(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Go\";})(),(function f000(){r" ascii
    $s3  = "eturn \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()" ascii
    $s4  = "\"Mt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s5  = "unction f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sj\";})(),(function f000(){ret" ascii
    $s6  = "ion f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"" ascii
    $s7  = "{return \"IAa\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(" ascii
    $s8  = "0(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s9  = "Bs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(functi" ascii
    $s10 = "0(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"NBs\"" ascii
    $s11 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(" ascii
    $s12 = "rn \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(f" ascii
    $s13 = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})()" ascii
    $s14 = ";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s15 = "n f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s16 = "rn \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s17 = " \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(func" ascii
    $s18 = "n f000(){return \"Sj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GG" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}