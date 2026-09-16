rule TTP_XOR_MULT_DOSStub_8261 {
  strings:
    $key_8261 = { d6 09 [2] a2 11 [2] e5 13 [2] a2 02 [2] ec 0e [2] e0 04 [2] f7 0f [2] ec 41 [2] d1 }

  condition:
    any of them
}