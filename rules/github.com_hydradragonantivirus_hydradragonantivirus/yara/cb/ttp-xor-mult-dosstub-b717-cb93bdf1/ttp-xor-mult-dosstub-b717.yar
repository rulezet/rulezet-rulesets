rule TTP_XOR_MULT_DOSStub_b717 {
  strings:
    $key_b717 = { e3 7f [2] 97 67 [2] d0 65 [2] 97 74 [2] d9 78 [2] d5 72 [2] c2 79 [2] d9 37 [2] e4 }

  condition:
    any of them
}