rule TTP_XOR_MULT_DOSStub_fc21 {
  strings:
    $key_fc21 = { a8 49 [2] dc 51 [2] 9b 53 [2] dc 42 [2] 92 4e [2] 9e 44 [2] 89 4f [2] 92 01 [2] af }

  condition:
    any of them
}