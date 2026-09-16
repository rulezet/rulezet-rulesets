rule TTP_XOR_MULT_DOSStub_b743 {
  strings:
    $key_b743 = { e3 2b [2] 97 33 [2] d0 31 [2] 97 20 [2] d9 2c [2] d5 26 [2] c2 2d [2] d9 63 [2] e4 }

  condition:
    any of them
}