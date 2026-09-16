rule TTP_XOR_MULT_DOSStub_8303 {
  strings:
    $key_8303 = { d7 6b [2] a3 73 [2] e4 71 [2] a3 60 [2] ed 6c [2] e1 66 [2] f6 6d [2] ed 23 [2] d0 }

  condition:
    any of them
}