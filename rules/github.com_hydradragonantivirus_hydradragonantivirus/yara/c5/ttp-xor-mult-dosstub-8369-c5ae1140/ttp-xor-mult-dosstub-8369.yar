rule TTP_XOR_MULT_DOSStub_8369 {
  strings:
    $key_8369 = { d7 01 [2] a3 19 [2] e4 1b [2] a3 0a [2] ed 06 [2] e1 0c [2] f6 07 [2] ed 49 [2] d0 }

  condition:
    any of them
}