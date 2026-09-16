rule TTP_XOR_MULT_DOSStub_ac97 {
  strings:
    $key_ac97 = { f8 ff [2] 8c e7 [2] cb e5 [2] 8c f4 [2] c2 f8 [2] ce f2 [2] d9 f9 [2] c2 b7 [2] ff }

  condition:
    any of them
}