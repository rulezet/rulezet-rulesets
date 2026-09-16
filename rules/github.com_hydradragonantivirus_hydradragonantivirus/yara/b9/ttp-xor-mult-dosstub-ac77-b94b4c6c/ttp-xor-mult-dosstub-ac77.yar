rule TTP_XOR_MULT_DOSStub_ac77 {
  strings:
    $key_ac77 = { f8 1f [2] 8c 07 [2] cb 05 [2] 8c 14 [2] c2 18 [2] ce 12 [2] d9 19 [2] c2 57 [2] ff }

  condition:
    any of them
}