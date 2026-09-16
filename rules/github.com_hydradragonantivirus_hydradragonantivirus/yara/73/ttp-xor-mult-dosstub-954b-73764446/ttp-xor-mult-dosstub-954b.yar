rule TTP_XOR_MULT_DOSStub_954b {
  strings:
    $key_954b = { c1 23 [2] b5 3b [2] f2 39 [2] b5 28 [2] fb 24 [2] f7 2e [2] e0 25 [2] fb 6b [2] c6 }

  condition:
    any of them
}