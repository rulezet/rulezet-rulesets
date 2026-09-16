rule _20160921_5e3ac68b2242250176f3300039d176f6_20160921_f7b964e1d5b6_2470 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash2       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"

  strings:
    $s1 = " f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MD" ascii
    $s2 = "unction f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s3 = "ion f000(){return \"Iq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s4 = ")(),(function f000(){return \"UEg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000" ascii
    $s5 = "urn \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s6 = "0(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Br\";}" ascii
    $s7 = "00(){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\"" ascii
    $s8 = "DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}