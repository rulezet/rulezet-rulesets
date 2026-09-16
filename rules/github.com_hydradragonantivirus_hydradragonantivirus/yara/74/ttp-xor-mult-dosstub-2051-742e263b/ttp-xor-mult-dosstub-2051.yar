rule TTP_XOR_MULT_DOSStub_2051 {
  strings:
    $key_2051 = { 74 39 [2] 00 21 [2] 47 23 [2] 00 32 [2] 4e 3e [2] 42 34 [2] 55 3f [2] 4e 71 [2] 73 }

  condition:
    any of them
}