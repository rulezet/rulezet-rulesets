rule TTP_XOR_MULT_DOSStub_ac21 {
  strings:
    $key_ac21 = { f8 49 [2] 8c 51 [2] cb 53 [2] 8c 42 [2] c2 4e [2] ce 44 [2] d9 4f [2] c2 01 [2] ff }

  condition:
    any of them
}