rule TTP_XOR_MULT_DOSStub_8307 {
  strings:
    $key_8307 = { d7 6f [2] a3 77 [2] e4 75 [2] a3 64 [2] ed 68 [2] e1 62 [2] f6 69 [2] ed 27 [2] d0 }

  condition:
    any of them
}