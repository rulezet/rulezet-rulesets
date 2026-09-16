rule TTP_XOR_MULT_DOSStub_8366 {
  strings:
    $key_8366 = { d7 0e [2] a3 16 [2] e4 14 [2] a3 05 [2] ed 09 [2] e1 03 [2] f6 08 [2] ed 46 [2] d0 }

  condition:
    any of them
}