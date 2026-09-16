rule TTP_XOR_MULT_DOSStub_b705 {
  strings:
    $key_b705 = { e3 6d [2] 97 75 [2] d0 77 [2] 97 66 [2] d9 6a [2] d5 60 [2] c2 6b [2] d9 25 [2] e4 }

  condition:
    any of them
}