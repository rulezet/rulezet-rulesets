rule TTP_XOR_MULT_DOSStub_fc22 {
  strings:
    $key_fc22 = { a8 4a [2] dc 52 [2] 9b 50 [2] dc 41 [2] 92 4d [2] 9e 47 [2] 89 4c [2] 92 02 [2] af }

  condition:
    any of them
}