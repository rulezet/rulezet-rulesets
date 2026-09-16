rule TTP_XOR_MULT_DOSStub_abf3 {
  strings:
    $key_abf3 = { ff 9b [2] 8b 83 [2] cc 81 [2] 8b 90 [2] c5 9c [2] c9 96 [2] de 9d [2] c5 d3 [2] f8 }

  condition:
    any of them
}