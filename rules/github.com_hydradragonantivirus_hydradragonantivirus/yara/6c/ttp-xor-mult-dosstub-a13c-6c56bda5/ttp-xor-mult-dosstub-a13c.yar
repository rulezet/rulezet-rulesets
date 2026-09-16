rule TTP_XOR_MULT_DOSStub_a13c {
  strings:
    $key_a13c = { f5 54 [2] 81 4c [2] c6 4e [2] 81 5f [2] cf 53 [2] c3 59 [2] d4 52 [2] cf 1c [2] f2 }

  condition:
    any of them
}