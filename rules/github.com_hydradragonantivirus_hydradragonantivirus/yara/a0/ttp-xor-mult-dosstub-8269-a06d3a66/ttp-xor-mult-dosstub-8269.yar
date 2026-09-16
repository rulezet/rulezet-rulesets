rule TTP_XOR_MULT_DOSStub_8269 {
  strings:
    $key_8269 = { d6 01 [2] a2 19 [2] e5 1b [2] a2 0a [2] ec 06 [2] e0 0c [2] f7 07 [2] ec 49 [2] d1 }

  condition:
    any of them
}