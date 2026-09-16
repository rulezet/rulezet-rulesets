rule TTP_XOR_MULT_DOSStub_ecb9 {
  strings:
    $key_ecb9 = { b8 d1 [2] cc c9 [2] 8b cb [2] cc da [2] 82 d6 [2] 8e dc [2] 99 d7 [2] 82 99 [2] bf }

  condition:
    any of them
}