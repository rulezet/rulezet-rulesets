rule TTP_XOR_MULT_DOSStub_bbc6 {
  strings:
    $key_bbc6 = { ef ae [2] 9b b6 [2] dc b4 [2] 9b a5 [2] d5 a9 [2] d9 a3 [2] ce a8 [2] d5 e6 [2] e8 }

  condition:
    any of them
}