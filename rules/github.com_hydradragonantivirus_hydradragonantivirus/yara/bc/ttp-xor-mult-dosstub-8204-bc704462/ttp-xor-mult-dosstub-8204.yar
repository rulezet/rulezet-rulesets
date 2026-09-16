rule TTP_XOR_MULT_DOSStub_8204 {
  strings:
    $key_8204 = { d6 6c [2] a2 74 [2] e5 76 [2] a2 67 [2] ec 6b [2] e0 61 [2] f7 6a [2] ec 24 [2] d1 }

  condition:
    any of them
}