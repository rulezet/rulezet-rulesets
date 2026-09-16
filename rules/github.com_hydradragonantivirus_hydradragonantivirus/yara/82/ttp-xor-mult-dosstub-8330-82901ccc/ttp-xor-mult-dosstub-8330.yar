rule TTP_XOR_MULT_DOSStub_8330 {
  strings:
    $key_8330 = { d7 58 [2] a3 40 [2] e4 42 [2] a3 53 [2] ed 5f [2] e1 55 [2] f6 5e [2] ed 10 [2] d0 }

  condition:
    any of them
}