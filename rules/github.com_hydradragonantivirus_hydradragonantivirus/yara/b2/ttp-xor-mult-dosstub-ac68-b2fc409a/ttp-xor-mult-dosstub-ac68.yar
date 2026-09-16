rule TTP_XOR_MULT_DOSStub_ac68 {
  strings:
    $key_ac68 = { f8 00 [2] 8c 18 [2] cb 1a [2] 8c 0b [2] c2 07 [2] ce 0d [2] d9 06 [2] c2 48 [2] ff }

  condition:
    any of them
}