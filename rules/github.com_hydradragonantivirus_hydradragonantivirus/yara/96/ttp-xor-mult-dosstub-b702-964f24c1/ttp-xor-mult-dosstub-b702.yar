rule TTP_XOR_MULT_DOSStub_b702 {
  strings:
    $key_b702 = { e3 6a [2] 97 72 [2] d0 70 [2] 97 61 [2] d9 6d [2] d5 67 [2] c2 6c [2] d9 22 [2] e4 }

  condition:
    any of them
}