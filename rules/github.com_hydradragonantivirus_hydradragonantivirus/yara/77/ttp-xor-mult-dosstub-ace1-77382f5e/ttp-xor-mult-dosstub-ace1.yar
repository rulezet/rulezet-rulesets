rule TTP_XOR_MULT_DOSStub_ace1 {
  strings:
    $key_ace1 = { f8 89 [2] 8c 91 [2] cb 93 [2] 8c 82 [2] c2 8e [2] ce 84 [2] d9 8f [2] c2 c1 [2] ff }

  condition:
    any of them
}