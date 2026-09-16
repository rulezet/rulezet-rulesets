rule _20160921_be882ab89423f06a9e76ba0cb72775fe_20160921_f3a36d70a836_1621 {
  meta:
    description = "datamaliciousorder - from files 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1  = "f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s2  = "unction f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){ret" ascii
    $s3  = ",(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){" ascii
    $s4  = "rn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s5  = " \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DNa\";})(),(fun" ascii
    $s6  = "),(function f000(){return \"SEo\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000()" ascii
    $s7  = "(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){re" ascii
    $s8  = "ion f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s9  = "Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"HJm\";})(),(functio" ascii
    $s10 = "n f000(){return \"Ml\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"W" ascii
    $s11 = "eturn \"Sj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s12 = "n f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}