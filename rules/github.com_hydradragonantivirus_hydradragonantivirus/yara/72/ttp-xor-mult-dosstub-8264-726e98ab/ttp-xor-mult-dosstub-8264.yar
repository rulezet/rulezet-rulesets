rule TTP_XOR_MULT_DOSStub_8264 {
  strings:
    $key_8264 = { d6 0c [2] a2 14 [2] e5 16 [2] a2 07 [2] ec 0b [2] e0 01 [2] f7 0a [2] ec 44 [2] d1 }

  condition:
    any of them
}