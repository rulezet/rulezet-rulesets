rule TTP_XOR_MULT_DOSStub_b243 {
  strings:
    $key_b243 = { e6 2b [2] 92 33 [2] d5 31 [2] 92 20 [2] dc 2c [2] d0 26 [2] c7 2d [2] dc 63 [2] e1 }

  condition:
    any of them
}