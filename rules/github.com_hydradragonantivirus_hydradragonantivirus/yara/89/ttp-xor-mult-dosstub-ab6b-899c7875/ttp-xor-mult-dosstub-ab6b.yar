rule TTP_XOR_MULT_DOSStub_ab6b {
  strings:
    $key_ab6b = { ff 03 [2] 8b 1b [2] cc 19 [2] 8b 08 [2] c5 04 [2] c9 0e [2] de 05 [2] c5 4b [2] f8 }

  condition:
    any of them
}