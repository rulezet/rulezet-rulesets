rule TTP_XOR_MULT_DOSStub_fc02 {
  strings:
    $key_fc02 = { a8 6a [2] dc 72 [2] 9b 70 [2] dc 61 [2] 92 6d [2] 9e 67 [2] 89 6c [2] 92 22 [2] af }

  condition:
    any of them
}