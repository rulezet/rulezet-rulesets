rule TTP_XOR_MULT_DOSStub_a72c {
  strings:
    $key_a72c = { f3 44 [2] 87 5c [2] c0 5e [2] 87 4f [2] c9 43 [2] c5 49 [2] d2 42 [2] c9 0c [2] f4 }

  condition:
    any of them
}