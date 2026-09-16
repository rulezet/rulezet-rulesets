rule TTP_XOR_MULT_DOSStub_93f4 {
  strings:
    $key_93f4 = { c7 9c [2] b3 84 [2] f4 86 [2] b3 97 [2] fd 9b [2] f1 91 [2] e6 9a [2] fd d4 [2] c0 }

  condition:
    any of them
}