rule TTP_XOR_MULT_DOSStub_93a6 {
  strings:
    $key_93a6 = { c7 ce [2] b3 d6 [2] f4 d4 [2] b3 c5 [2] fd c9 [2] f1 c3 [2] e6 c8 [2] fd 86 [2] c0 }

  condition:
    any of them
}