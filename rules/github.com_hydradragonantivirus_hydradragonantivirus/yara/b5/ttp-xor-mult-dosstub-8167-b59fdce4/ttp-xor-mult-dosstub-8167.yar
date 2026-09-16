rule TTP_XOR_MULT_DOSStub_8167 {
  strings:
    $key_8167 = { d5 0f [2] a1 17 [2] e6 15 [2] a1 04 [2] ef 08 [2] e3 02 [2] f4 09 [2] ef 47 [2] d2 }

  condition:
    any of them
}