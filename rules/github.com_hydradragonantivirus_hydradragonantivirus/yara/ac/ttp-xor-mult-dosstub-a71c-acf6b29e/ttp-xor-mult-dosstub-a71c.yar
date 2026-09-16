rule TTP_XOR_MULT_DOSStub_a71c {
  strings:
    $key_a71c = { f3 74 [2] 87 6c [2] c0 6e [2] 87 7f [2] c9 73 [2] c5 79 [2] d2 72 [2] c9 3c [2] f4 }

  condition:
    any of them
}