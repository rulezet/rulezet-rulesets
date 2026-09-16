rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_24cca85b9483_4721 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash3       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash4       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash5       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = "GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"XTn\";})(),(functio" ascii
    $s2 = "n \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(f" ascii
    $s3 = "f000(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn" ascii
    $s4 = " \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s5 = "00(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Wb\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}