rule TTP_XOR_MULT_DOSStub_107b {
  strings:
    $key_107b = { 44 13 [2] 30 0b [2] 77 09 [2] 30 18 [2] 7e 14 [2] 72 1e [2] 65 15 [2] 7e 5b [2] 43 }

  condition:
    any of them
}