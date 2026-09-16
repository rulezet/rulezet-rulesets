rule TTP_XOR_MULT_DOSStub_fc3f {
  strings:
    $key_fc3f = { a8 57 [2] dc 4f [2] 9b 4d [2] dc 5c [2] 92 50 [2] 9e 5a [2] 89 51 [2] 92 1f [2] af }

  condition:
    any of them
}