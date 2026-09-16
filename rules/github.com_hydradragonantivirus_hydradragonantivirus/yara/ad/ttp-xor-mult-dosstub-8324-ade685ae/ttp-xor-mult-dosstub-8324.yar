rule TTP_XOR_MULT_DOSStub_8324 {
  strings:
    $key_8324 = { d7 4c [2] a3 54 [2] e4 56 [2] a3 47 [2] ed 4b [2] e1 41 [2] f6 4a [2] ed 04 [2] d0 }

  condition:
    any of them
}