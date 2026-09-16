rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_42c93aee0243_170 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash3       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash4       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash5       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash6       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash7       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"
    hash8       = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash9       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"
    hash10      = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"
    hash11      = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"
    hash12      = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1  = "Kw\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s2  = " f000(){return \"MJq\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s3  = "\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Ml\";})(),(function f" ascii
    $s4  = ",(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"UEg\";})(),(function f000()" ascii
    $s5  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){retur" ascii
    $s6  = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NYh\";})(),(fu" ascii
    $s7  = "(),(function f000(){return \"PTs\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(" ascii
    $s8  = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"BQb\";})(),(function f" ascii
    $s9  = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000" ascii
    $s10 = "on f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s11 = "return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Yz\";})()" ascii
    $s12 = "0(){return \"NBs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";" ascii
    $s13 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Oe\";}" ascii
    $s14 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DN" ascii
    $s15 = "MBb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s16 = "00(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s17 = " \"Br\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Mt\";})(),(functi" ascii
    $s18 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return" ascii
    $s19 = ";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Do\";})(),(function f00" ascii
    $s20 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}