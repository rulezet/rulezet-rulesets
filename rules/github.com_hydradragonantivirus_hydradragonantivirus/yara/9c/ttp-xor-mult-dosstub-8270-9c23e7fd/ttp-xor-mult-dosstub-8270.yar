rule TTP_XOR_MULT_DOSStub_8270 {
  strings:
    $key_8270 = { d6 18 [2] a2 00 [2] e5 02 [2] a2 13 [2] ec 1f [2] e0 15 [2] f7 1e [2] ec 50 [2] d1 }

  condition:
    any of them
}