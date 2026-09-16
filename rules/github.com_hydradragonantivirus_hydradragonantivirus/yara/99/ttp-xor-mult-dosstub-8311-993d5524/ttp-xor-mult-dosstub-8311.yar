rule TTP_XOR_MULT_DOSStub_8311 {
  strings:
    $key_8311 = { d7 79 [2] a3 61 [2] e4 63 [2] a3 72 [2] ed 7e [2] e1 74 [2] f6 7f [2] ed 31 [2] d0 }

  condition:
    any of them
}