rule TTP_XOR_MULT_DOSStub_93f5 {
  strings:
    $key_93f5 = { c7 9d [2] b3 85 [2] f4 87 [2] b3 96 [2] fd 9a [2] f1 90 [2] e6 9b [2] fd d5 [2] c0 }

  condition:
    any of them
}