rule TTP_XOR_MULT_DOSStub_8253 {
  strings:
    $key_8253 = { d6 3b [2] a2 23 [2] e5 21 [2] a2 30 [2] ec 3c [2] e0 36 [2] f7 3d [2] ec 73 [2] d1 }

  condition:
    any of them
}