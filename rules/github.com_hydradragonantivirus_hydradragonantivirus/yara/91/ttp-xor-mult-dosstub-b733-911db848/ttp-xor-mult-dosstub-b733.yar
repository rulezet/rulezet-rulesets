rule TTP_XOR_MULT_DOSStub_b733 {
  strings:
    $key_b733 = { e3 5b [2] 97 43 [2] d0 41 [2] 97 50 [2] d9 5c [2] d5 56 [2] c2 5d [2] d9 13 [2] e4 }

  condition:
    any of them
}