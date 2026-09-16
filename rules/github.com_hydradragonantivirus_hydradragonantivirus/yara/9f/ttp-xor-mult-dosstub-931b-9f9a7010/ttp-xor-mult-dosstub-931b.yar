rule TTP_XOR_MULT_DOSStub_931b {
  strings:
    $key_931b = { c7 73 [2] b3 6b [2] f4 69 [2] b3 78 [2] fd 74 [2] f1 7e [2] e6 75 [2] fd 3b [2] c0 }

  condition:
    any of them
}