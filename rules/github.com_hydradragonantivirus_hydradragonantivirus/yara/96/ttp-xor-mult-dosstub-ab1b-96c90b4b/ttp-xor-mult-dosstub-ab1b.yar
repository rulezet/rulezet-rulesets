rule TTP_XOR_MULT_DOSStub_ab1b {
  strings:
    $key_ab1b = { ff 73 [2] 8b 6b [2] cc 69 [2] 8b 78 [2] c5 74 [2] c9 7e [2] de 75 [2] c5 3b [2] f8 }

  condition:
    any of them
}