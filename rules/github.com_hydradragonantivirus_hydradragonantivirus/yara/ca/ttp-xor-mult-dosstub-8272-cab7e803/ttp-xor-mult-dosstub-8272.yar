rule TTP_XOR_MULT_DOSStub_8272 {
  strings:
    $key_8272 = { d6 1a [2] a2 02 [2] e5 00 [2] a2 11 [2] ec 1d [2] e0 17 [2] f7 1c [2] ec 52 [2] d1 }

  condition:
    any of them
}