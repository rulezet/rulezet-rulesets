rule TTP_XOR_MULT_DOSStub_8279 {
  strings:
    $key_8279 = { d6 11 [2] a2 09 [2] e5 0b [2] a2 1a [2] ec 16 [2] e0 1c [2] f7 17 [2] ec 59 [2] d1 }

  condition:
    any of them
}