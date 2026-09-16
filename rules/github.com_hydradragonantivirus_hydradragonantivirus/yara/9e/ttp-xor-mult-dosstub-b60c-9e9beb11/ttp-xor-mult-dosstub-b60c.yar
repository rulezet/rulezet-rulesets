rule TTP_XOR_MULT_DOSStub_b60c {
  strings:
    $key_b60c = { e2 64 [2] 96 7c [2] d1 7e [2] 96 6f [2] d8 63 [2] d4 69 [2] c3 62 [2] d8 2c [2] e5 }

  condition:
    any of them
}