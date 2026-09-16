rule TTP_XOR_MULT_DOSStub_871c {
  strings:
    $key_871c = { d3 74 [2] a7 6c [2] e0 6e [2] a7 7f [2] e9 73 [2] e5 79 [2] f2 72 [2] e9 3c [2] d4 }

  condition:
    any of them
}