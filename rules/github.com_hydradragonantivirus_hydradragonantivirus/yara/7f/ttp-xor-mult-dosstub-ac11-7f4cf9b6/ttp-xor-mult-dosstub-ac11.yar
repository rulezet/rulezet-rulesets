rule TTP_XOR_MULT_DOSStub_ac11 {
  strings:
    $key_ac11 = { f8 79 [2] 8c 61 [2] cb 63 [2] 8c 72 [2] c2 7e [2] ce 74 [2] d9 7f [2] c2 31 [2] ff }

  condition:
    any of them
}