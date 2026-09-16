rule TTP_XOR_MULT_DOSStub_8300 {
  strings:
    $key_8300 = { d7 68 [2] a3 70 [2] e4 72 [2] a3 63 [2] ed 6f [2] e1 65 [2] f6 6e [2] ed 20 [2] d0 }

  condition:
    any of them
}