rule TTP_XOR_MULT_DOSStub_8233 {
  strings:
    $key_8233 = { d6 5b [2] a2 43 [2] e5 41 [2] a2 50 [2] ec 5c [2] e0 56 [2] f7 5d [2] ec 13 [2] d1 }

  condition:
    any of them
}