rule TTP_XOR_MULT_DOSStub_bad1 {
  strings:
    $key_bad1 = { ee b9 [2] 9a a1 [2] dd a3 [2] 9a b2 [2] d4 be [2] d8 b4 [2] cf bf [2] d4 f1 [2] e9 }

  condition:
    any of them
}