rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_18f3e0383dae_254 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash3       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash4       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash5       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash6       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash7       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash8       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"
    hash9       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Uo\";})(),(function f000(){retu" ascii
    $s2  = "return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Uo\";})()" ascii
    $s3  = "\"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Vu\";})(),(functi" ascii
    $s4  = "rn \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"BQb\";})(),(f" ascii
    $s5  = "f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Kw" ascii
    $s6  = "00(){return \"HJm\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Do" ascii
    $s7  = "),(function f000(){return \"Sj\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000()" ascii
    $s8  = "ction f000(){return \"BMj\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){retur" ascii
    $s9  = "),(function f000(){return \"Vu\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"NYh\";})(),(function f000(){" ascii
    $s10 = "return \"Go\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()" ascii
    $s11 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"L" ascii
    $s12 = "Vj\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Kw\";})(),(functio" ascii
    $s13 = "nction f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii
    $s14 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"MBb\";})(),(fu" ascii
    $s15 = " \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s16 = "s\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s17 = "return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Br\";})()" ascii
    $s18 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(fu" ascii
    $s19 = "00(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Wy\";" ascii
    $s20 = "n \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}