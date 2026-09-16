rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_69015d5cf863_3649 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1 = "unction f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){ret" ascii
    $s2 = "turn \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})()," ascii
    $s3 = "ion f000(){return \"BQb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "n f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"D" ascii
    $s5 = "u\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s6 = "\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}