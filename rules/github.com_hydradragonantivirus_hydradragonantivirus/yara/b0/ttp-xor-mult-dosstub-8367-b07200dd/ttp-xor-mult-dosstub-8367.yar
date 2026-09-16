rule TTP_XOR_MULT_DOSStub_8367 {
  strings:
    $key_8367 = { d7 0f [2] a3 17 [2] e4 15 [2] a3 04 [2] ed 08 [2] e1 02 [2] f6 09 [2] ed 47 [2] d0 }

  condition:
    any of them
}