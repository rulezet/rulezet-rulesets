rule TTP_XOR_MULT_DOSStub_93f3 {
  strings:
    $key_93f3 = { c7 9b [2] b3 83 [2] f4 81 [2] b3 90 [2] fd 9c [2] f1 96 [2] e6 9d [2] fd d3 [2] c0 }

  condition:
    any of them
}