rule TTP_XOR_MULT_DOSStub_3051 {
  strings:
    $key_3051 = { 64 39 [2] 10 21 [2] 57 23 [2] 10 32 [2] 5e 3e [2] 52 34 [2] 45 3f [2] 5e 71 [2] 63 }

  condition:
    any of them
}