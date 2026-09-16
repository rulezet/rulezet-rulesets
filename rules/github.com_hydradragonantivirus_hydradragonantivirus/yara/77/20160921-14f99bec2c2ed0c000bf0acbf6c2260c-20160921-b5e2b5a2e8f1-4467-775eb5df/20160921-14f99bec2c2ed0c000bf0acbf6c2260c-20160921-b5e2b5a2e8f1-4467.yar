rule _20160921_14f99bec2c2ed0c000bf0acbf6c2260c_20160921_b5e2b5a2e8f1_4467 {
  meta:
    description = "datamaliciousorder - from files 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash2       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"
    hash3       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "n f000(){return \"Wy\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GG" ascii
    $s2 = "f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MD" ascii
    $s3 = "0(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\"" ascii
    $s4 = ",(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){" ascii
    $s5 = "000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}