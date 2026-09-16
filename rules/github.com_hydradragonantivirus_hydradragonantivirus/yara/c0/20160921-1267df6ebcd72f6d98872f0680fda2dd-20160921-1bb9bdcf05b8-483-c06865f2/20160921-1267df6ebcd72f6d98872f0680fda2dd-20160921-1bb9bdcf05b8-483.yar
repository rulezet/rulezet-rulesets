rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_1bb9bdcf05b8_483 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_52ab3697b827675e3be965f7171e236d.js, 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_8644cb559dff4747b398e56be3b4ea85.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js, 20160921_ce9aea7615ba4a71719a9c0d7f838fc1.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash3       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash4       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash5       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash6       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash7       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash8       = "90a876a1d91ded80337b02adca1c227fdf5b5a96381a62397d3485e5e8ea108b"
    hash9       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash10      = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash11      = "d92ab3635a987485347ef1a40e84d56adf54d5da5be50490856e0386b6ccabda"
    hash12      = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash13      = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"
    hash14      = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash15      = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"
    hash16      = "1dfc225800b3b802cbdd9312a3198f5eb4bbcdb06d5f9ffd026bb3fb4f5cf4e6"
    hash17      = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1  = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"YAv\";})(),(function" ascii
    $s2  = "{return \"Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s3  = " \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s4  = " fuck(){return \"GWo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s5  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return" ascii
    $s6  = "{return \"We\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s7  = "k(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Mw\";" ascii
    $s8  = "uck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\"" ascii
    $s9  = "rn \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s10 = "IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ik\";})(),(function" ascii
    $s11 = "unction fuck(){return \"Wo0\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){retu" ascii
    $s12 = ")(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"DAa\";})(),(function fuck(" ascii
    $s13 = "n fuck(){return \"Ar\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"X" ascii
    $s14 = "ction fuck(){return \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s15 = "k(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"OPz\"" ascii
    $s16 = " \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s17 = "){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";}" ascii
    $s18 = "fuck(){return \"Ug\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu" ascii
    $s19 = "eturn \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s20 = "Pu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xw\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}