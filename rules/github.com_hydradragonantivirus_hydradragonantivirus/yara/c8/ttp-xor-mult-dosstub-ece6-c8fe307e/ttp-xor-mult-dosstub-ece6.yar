rule TTP_XOR_MULT_DOSStub_ece6 {
  strings:
    $key_ece6 = { b8 8e [2] cc 96 [2] 8b 94 [2] cc 85 [2] 82 89 [2] 8e 83 [2] 99 88 [2] 82 c6 [2] bf }

  condition:
    any of them
}