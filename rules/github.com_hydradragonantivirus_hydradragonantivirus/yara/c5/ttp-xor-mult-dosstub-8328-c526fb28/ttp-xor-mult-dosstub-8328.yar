rule TTP_XOR_MULT_DOSStub_8328 {
  strings:
    $key_8328 = { d7 40 [2] a3 58 [2] e4 5a [2] a3 4b [2] ed 47 [2] e1 4d [2] f6 46 [2] ed 08 [2] d0 }

  condition:
    any of them
}