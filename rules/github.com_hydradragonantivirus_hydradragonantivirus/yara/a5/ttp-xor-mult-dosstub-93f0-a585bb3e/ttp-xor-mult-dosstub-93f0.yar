rule TTP_XOR_MULT_DOSStub_93f0 {
  strings:
    $key_93f0 = { c7 98 [2] b3 80 [2] f4 82 [2] b3 93 [2] fd 9f [2] f1 95 [2] e6 9e [2] fd d0 [2] c0 }

  condition:
    any of them
}