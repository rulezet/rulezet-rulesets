rule TTP_XOR_MULT_DOSStub_951b {
  strings:
    $key_951b = { c1 73 [2] b5 6b [2] f2 69 [2] b5 78 [2] fb 74 [2] f7 7e [2] e0 75 [2] fb 3b [2] c6 }

  condition:
    any of them
}