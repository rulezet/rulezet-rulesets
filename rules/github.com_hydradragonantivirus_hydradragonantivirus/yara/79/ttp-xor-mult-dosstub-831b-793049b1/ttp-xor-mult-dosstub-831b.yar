rule TTP_XOR_MULT_DOSStub_831b {
  strings:
    $key_831b = { d7 73 [2] a3 6b [2] e4 69 [2] a3 78 [2] ed 74 [2] e1 7e [2] f6 75 [2] ed 3b [2] d0 }

  condition:
    any of them
}