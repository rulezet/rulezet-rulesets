rule TTP_XOR_MULT_DOSStub_836e {
  strings:
    $key_836e = { d7 06 [2] a3 1e [2] e4 1c [2] a3 0d [2] ed 01 [2] e1 0b [2] f6 00 [2] ed 4e [2] d0 }

  condition:
    any of them
}