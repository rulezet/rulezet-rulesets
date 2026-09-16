rule TTP_XOR_MULT_DOSStub_8263 {
  strings:
    $key_8263 = { d6 0b [2] a2 13 [2] e5 11 [2] a2 00 [2] ec 0c [2] e0 06 [2] f7 0d [2] ec 43 [2] d1 }

  condition:
    any of them
}