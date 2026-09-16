rule TTP_XOR_MULT_DOSStub_93f7 {
  strings:
    $key_93f7 = { c7 9f [2] b3 87 [2] f4 85 [2] b3 94 [2] fd 98 [2] f1 92 [2] e6 99 [2] fd d7 [2] c0 }

  condition:
    any of them
}