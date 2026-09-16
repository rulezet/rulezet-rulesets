rule TTP_XOR_MULT_DOSStub_b629 {
  strings:
    $key_b629 = { e2 41 [2] 96 59 [2] d1 5b [2] 96 4a [2] d8 46 [2] d4 4c [2] c3 47 [2] d8 09 [2] e5 }

  condition:
    any of them
}