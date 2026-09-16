rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_1568884c6d02_657 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_4357cd536e8c7d04b6d87c9010da5db8.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160921_ca70c2e5223139fb829c45d71c694e10.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js, 20160921_fb6312e3d81966654b016b9b32d471ac.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash3       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash4       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash5       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash6       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash7       = "aa03b8f8bd18b6425bd0435f38ca6501c2932bd998eaa0c2be7420c50212affb"
    hash8       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash9       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash10      = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash11      = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash12      = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash13      = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash14      = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash15      = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"
    hash16      = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash17      = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash18      = "06efdd8c0262a51372ea085744e30220d9e93e45b2bf9ef29d7e71b27174d2fc"
    hash19      = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"
    hash20      = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"
    hash21      = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"
    hash22      = "e9183fcae238e67df02c94cc13c7f9ce436709e3bd1fdaee8caa1fb15e4c0f81"
    hash23      = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"
    hash24      = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"
    hash25      = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1  = "on f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s2  = "\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f0" ascii
    $s3  = "(){return \"ZGq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";" ascii
    $s4  = "0(){return \"SEo\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\"" ascii
    $s5  = ",(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){r" ascii
    $s6  = "ction f000(){return \"Br\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return" ascii
    $s7  = "rn \"Nv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s8  = ",(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){r" ascii
    $s9  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Go\";})(),(function f00" ascii
    $s10 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){ret" ascii
    $s11 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){retu" ascii
    $s12 = "{return \"DYx\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"EZu\";})" ascii
    $s13 = "BMj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s14 = " f000(){return \"Nv\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Qz" ascii
    $s15 = "{return \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})()" ascii
    $s16 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Qj" ascii
    $s17 = " \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s18 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb" ascii
    $s19 = "c\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s20 = "turn \"BQb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}