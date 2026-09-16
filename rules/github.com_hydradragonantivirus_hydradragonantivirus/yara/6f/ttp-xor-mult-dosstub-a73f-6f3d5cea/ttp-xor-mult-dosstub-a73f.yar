rule TTP_XOR_MULT_DOSStub_a73f {
  strings:
    $key_a73f = { f3 57 [2] 87 4f [2] c0 4d [2] 87 5c [2] c9 50 [2] c5 5a [2] d2 51 [2] c9 1f [2] f4 }

  condition:
    any of them
}