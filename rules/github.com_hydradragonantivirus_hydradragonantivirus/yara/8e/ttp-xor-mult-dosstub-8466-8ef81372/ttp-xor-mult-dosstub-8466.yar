rule TTP_XOR_MULT_DOSStub_8466 {
  strings:
    $key_8466 = { d0 0e [2] a4 16 [2] e3 14 [2] a4 05 [2] ea 09 [2] e6 03 [2] f1 08 [2] ea 46 [2] d7 }

  condition:
    any of them
}