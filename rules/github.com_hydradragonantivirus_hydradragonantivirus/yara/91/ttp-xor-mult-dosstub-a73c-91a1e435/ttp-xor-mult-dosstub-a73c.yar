rule TTP_XOR_MULT_DOSStub_a73c {
  strings:
    $key_a73c = { f3 54 [2] 87 4c [2] c0 4e [2] 87 5f [2] c9 53 [2] c5 59 [2] d2 52 [2] c9 1c [2] f4 }

  condition:
    any of them
}