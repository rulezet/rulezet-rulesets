rule TTP_XOR_MULT_DOSStub_b719 {
  strings:
    $key_b719 = { e3 71 [2] 97 69 [2] d0 6b [2] 97 7a [2] d9 76 [2] d5 7c [2] c2 77 [2] d9 39 [2] e4 }

  condition:
    any of them
}