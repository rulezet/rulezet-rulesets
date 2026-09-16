rule TTP_XOR_MULT_DOSStub_ace7 {
  strings:
    $key_ace7 = { f8 8f [2] 8c 97 [2] cb 95 [2] 8c 84 [2] c2 88 [2] ce 82 [2] d9 89 [2] c2 c7 [2] ff }

  condition:
    any of them
}