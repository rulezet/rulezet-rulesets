rule TTP_XOR_MULT_DOSStub_fc1c {
  strings:
    $key_fc1c = { a8 74 [2] dc 6c [2] 9b 6e [2] dc 7f [2] 92 73 [2] 9e 79 [2] 89 72 [2] 92 3c [2] af }

  condition:
    any of them
}