rule TTP_XOR_MULT_DOSStub_ab4b {
  strings:
    $key_ab4b = { ff 23 [2] 8b 3b [2] cc 39 [2] 8b 28 [2] c5 24 [2] c9 2e [2] de 25 [2] c5 6b [2] f8 }

  condition:
    any of them
}