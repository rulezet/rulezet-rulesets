rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_1568884c6d02_766 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash3       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash4       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash5       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash6       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash7       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash8       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash9       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash10      = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash11      = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"
    hash12      = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"
    hash13      = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1  = "){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";}" ascii
    $s2  = "function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Sq\";})(),(function f000(){re" ascii
    $s3  = " \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s4  = "nction f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii
    $s5  = "rn \"Yz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s6  = "(),(function f000(){return \"Km\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s7  = "(),(function f000(){return \"Sj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s8  = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DYx\";" ascii
    $s9  = "000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br" ascii
    $s10 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Km\";" ascii
    $s11 = " f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s12 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"TKp\";})(),(funct" ascii
    $s13 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DAp" ascii
    $s14 = "function f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Rh\";})(),(function f000(){retu" ascii
    $s15 = "ion f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"YTp\";})(),(function f000(){return" ascii
    $s16 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s17 = "eturn \"MBb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Qz\";})()," ascii
    $s18 = "ion f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s19 = " \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"YTp\";})(),(fun" ascii
    $s20 = "return \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}