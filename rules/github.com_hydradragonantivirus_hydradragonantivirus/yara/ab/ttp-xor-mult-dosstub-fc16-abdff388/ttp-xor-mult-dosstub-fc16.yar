rule TTP_XOR_MULT_DOSStub_fc16 {
  strings:
    $key_fc16 = { a8 7e [2] dc 66 [2] 9b 64 [2] dc 75 [2] 92 79 [2] 9e 73 [2] 89 78 [2] 92 36 [2] af }

  condition:
    any of them
}