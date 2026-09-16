rule TTP_XOR_MULT_DOSStub_a13f {
  strings:
    $key_a13f = { f5 57 [2] 81 4f [2] c6 4d [2] 81 5c [2] cf 50 [2] c3 5a [2] d4 51 [2] cf 1f [2] f2 }

  condition:
    any of them
}