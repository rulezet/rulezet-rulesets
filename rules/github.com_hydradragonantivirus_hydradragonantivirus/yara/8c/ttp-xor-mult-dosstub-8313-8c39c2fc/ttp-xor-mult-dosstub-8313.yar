rule TTP_XOR_MULT_DOSStub_8313 {
  strings:
    $key_8313 = { d7 7b [2] a3 63 [2] e4 61 [2] a3 70 [2] ed 7c [2] e1 76 [2] f6 7d [2] ed 33 [2] d0 }

  condition:
    any of them
}