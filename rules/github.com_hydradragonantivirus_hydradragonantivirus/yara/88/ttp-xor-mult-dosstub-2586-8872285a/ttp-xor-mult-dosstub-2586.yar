rule TTP_XOR_MULT_DOSStub_2586 {
  strings:
    $key_2586 = { 71 ee [2] 05 f6 [2] 42 f4 [2] 05 e5 [2] 4b e9 [2] 47 e3 [2] 50 e8 [2] 4b a6 [2] 76 }

  condition:
    any of them
}