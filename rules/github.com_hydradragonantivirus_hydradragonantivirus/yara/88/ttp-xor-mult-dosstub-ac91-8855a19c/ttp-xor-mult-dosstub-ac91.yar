rule TTP_XOR_MULT_DOSStub_ac91 {
  strings:
    $key_ac91 = { f8 f9 [2] 8c e1 [2] cb e3 [2] 8c f2 [2] c2 fe [2] ce f4 [2] d9 ff [2] c2 b1 [2] ff }

  condition:
    any of them
}