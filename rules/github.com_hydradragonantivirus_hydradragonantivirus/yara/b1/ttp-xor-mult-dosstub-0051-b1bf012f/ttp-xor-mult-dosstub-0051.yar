rule TTP_XOR_MULT_DOSStub_0051 {
  strings:
    $key_0051 = { 54 39 [2] 20 21 [2] 67 23 [2] 20 32 [2] 6e 3e [2] 62 34 [2] 75 3f [2] 6e 71 [2] 53 }

  condition:
    any of them
}