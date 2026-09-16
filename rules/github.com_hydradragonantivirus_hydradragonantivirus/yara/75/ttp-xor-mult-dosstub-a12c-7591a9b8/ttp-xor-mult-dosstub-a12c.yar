rule TTP_XOR_MULT_DOSStub_a12c {
  strings:
    $key_a12c = { f5 44 [2] 81 5c [2] c6 5e [2] 81 4f [2] cf 43 [2] c3 49 [2] d4 42 [2] cf 0c [2] f2 }

  condition:
    any of them
}