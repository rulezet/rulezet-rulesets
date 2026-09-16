rule TTP_XOR_MULT_DOSStub_fc5d {
  strings:
    $key_fc5d = { a8 35 [2] dc 2d [2] 9b 2f [2] dc 3e [2] 92 32 [2] 9e 38 [2] 89 33 [2] 92 7d [2] af }

  condition:
    any of them
}