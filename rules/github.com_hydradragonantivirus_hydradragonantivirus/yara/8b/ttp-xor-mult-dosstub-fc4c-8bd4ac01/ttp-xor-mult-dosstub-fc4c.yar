rule TTP_XOR_MULT_DOSStub_fc4c {
  strings:
    $key_fc4c = { a8 24 [2] dc 3c [2] 9b 3e [2] dc 2f [2] 92 23 [2] 9e 29 [2] 89 22 [2] 92 6c [2] af }

  condition:
    any of them
}