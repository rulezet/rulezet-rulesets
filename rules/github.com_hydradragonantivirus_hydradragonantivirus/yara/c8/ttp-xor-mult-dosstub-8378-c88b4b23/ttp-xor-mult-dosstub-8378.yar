rule TTP_XOR_MULT_DOSStub_8378 {
  strings:
    $key_8378 = { d7 10 [2] a3 08 [2] e4 0a [2] a3 1b [2] ed 17 [2] e1 1d [2] f6 16 [2] ed 58 [2] d0 }

  condition:
    any of them
}