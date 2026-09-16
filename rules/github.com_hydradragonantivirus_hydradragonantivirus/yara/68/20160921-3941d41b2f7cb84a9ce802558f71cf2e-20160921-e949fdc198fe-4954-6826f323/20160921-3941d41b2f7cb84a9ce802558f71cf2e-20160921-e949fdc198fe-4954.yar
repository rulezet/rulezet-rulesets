rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_e949fdc198fe_4954 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_e949fdc198fee477717395093f5853e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"

  strings:
    $s1 = "ction f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return" ascii
    $s2 = "n \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(func" ascii
    $s3 = ")(),(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})(),(function f000" ascii
    $s4 = "(){return \"QDg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";}" ascii
    $s5 = "eturn \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}