rule TTP_XOR_MULT_DOSStub_8ab9 {
  strings:
    $key_8ab9 = { de d1 [2] aa c9 [2] ed cb [2] aa da [2] e4 d6 [2] e8 dc [2] ff d7 [2] e4 99 [2] d9 }

  condition:
    any of them
}