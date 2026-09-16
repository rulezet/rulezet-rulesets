rule TTP_XOR_MULT_DOSStub_fc32 {
  strings:
    $key_fc32 = { a8 5a [2] dc 42 [2] 9b 40 [2] dc 51 [2] 92 5d [2] 9e 57 [2] 89 5c [2] 92 12 [2] af }

  condition:
    any of them
}