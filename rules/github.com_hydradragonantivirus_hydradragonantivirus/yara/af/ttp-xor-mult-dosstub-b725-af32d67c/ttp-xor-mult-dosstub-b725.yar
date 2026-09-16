rule TTP_XOR_MULT_DOSStub_b725 {
  strings:
    $key_b725 = { e3 4d [2] 97 55 [2] d0 57 [2] 97 46 [2] d9 4a [2] d5 40 [2] c2 4b [2] d9 05 [2] e4 }

  condition:
    any of them
}