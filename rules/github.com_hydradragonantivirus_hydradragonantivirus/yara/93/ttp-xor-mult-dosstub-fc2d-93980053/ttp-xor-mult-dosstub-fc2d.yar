rule TTP_XOR_MULT_DOSStub_fc2d {
  strings:
    $key_fc2d = { a8 45 [2] dc 5d [2] 9b 5f [2] dc 4e [2] 92 42 [2] 9e 48 [2] 89 43 [2] 92 0d [2] af }

  condition:
    any of them
}