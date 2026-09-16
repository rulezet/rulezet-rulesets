rule TTP_XOR_MULT_DOSStub_fc5e {
  strings:
    $key_fc5e = { a8 36 [2] dc 2e [2] 9b 2c [2] dc 3d [2] 92 31 [2] 9e 3b [2] 89 30 [2] 92 7e [2] af }

  condition:
    any of them
}