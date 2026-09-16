rule TTP_XOR_MULT_DOSStub_8209 {
  strings:
    $key_8209 = { d6 61 [2] a2 79 [2] e5 7b [2] a2 6a [2] ec 66 [2] e0 6c [2] f7 67 [2] ec 29 [2] d1 }

  condition:
    any of them
}