rule TTP_XOR_MULT_DOSStub_fc0e {
  strings:
    $key_fc0e = { a8 66 [2] dc 7e [2] 9b 7c [2] dc 6d [2] 92 61 [2] 9e 6b [2] 89 60 [2] 92 2e [2] af }

  condition:
    any of them
}