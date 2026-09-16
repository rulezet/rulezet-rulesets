rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_18f3e0383dae_2735 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash3       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash4       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash5       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash6       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash7       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash8       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash9       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash10      = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"
    hash11      = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"
    hash12      = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"
    hash13      = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Tb\";})()" ascii
    $s2 = "(){return \"SEo\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";" ascii
    $s3 = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"BMj\";})(),(functi" ascii
    $s4 = " \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s5 = "nction f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Mc\";})(),(function f000(){retur" ascii
    $s6 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"" ascii
    $s7 = "urn \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Mc\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}