rule TTP_XOR_MULT_DOSStub_93f9 {
  strings:
    $key_93f9 = { c7 91 [2] b3 89 [2] f4 8b [2] b3 9a [2] fd 96 [2] f1 9c [2] e6 97 [2] fd d9 [2] c0 }

  condition:
    any of them
}