rule TTP_XOR_MULT_DOSStub_93e9 {
  strings:
    $key_93e9 = { c7 81 [2] b3 99 [2] f4 9b [2] b3 8a [2] fd 86 [2] f1 8c [2] e6 87 [2] fd c9 [2] c0 }

  condition:
    any of them
}