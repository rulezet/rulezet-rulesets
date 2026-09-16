rule TTP_XOR_MULT_DOSStub_8361 {
  strings:
    $key_8361 = { d7 09 [2] a3 11 [2] e4 13 [2] a3 02 [2] ed 0e [2] e1 04 [2] f6 0f [2] ed 41 [2] d0 }

  condition:
    any of them
}