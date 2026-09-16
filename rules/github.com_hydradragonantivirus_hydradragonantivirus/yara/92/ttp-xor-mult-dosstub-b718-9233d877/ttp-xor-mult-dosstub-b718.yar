rule TTP_XOR_MULT_DOSStub_b718 {
  strings:
    $key_b718 = { e3 70 [2] 97 68 [2] d0 6a [2] 97 7b [2] d9 77 [2] d5 7d [2] c2 76 [2] d9 38 [2] e4 }

  condition:
    any of them
}