rule TTP_XOR_MULT_DOSStub_6051 {
  strings:
    $key_6051 = { 34 39 [2] 40 21 [2] 07 23 [2] 40 32 [2] 0e 3e [2] 02 34 [2] 15 3f [2] 0e 71 [2] 33 }

  condition:
    any of them
}