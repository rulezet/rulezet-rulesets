rule TTP_XOR_MULT_DOSStub_bbc1 {
  strings:
    $key_bbc1 = { ef a9 [2] 9b b1 [2] dc b3 [2] 9b a2 [2] d5 ae [2] d9 a4 [2] ce af [2] d5 e1 [2] e8 }

  condition:
    any of them
}