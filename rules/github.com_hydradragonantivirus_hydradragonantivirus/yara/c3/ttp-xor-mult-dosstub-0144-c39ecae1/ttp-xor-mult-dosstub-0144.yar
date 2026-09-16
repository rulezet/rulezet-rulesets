rule TTP_XOR_MULT_DOSStub_0144 {
  strings:
    $key_0144 = { 55 2c [2] 21 34 [2] 66 36 [2] 21 27 [2] 6f 2b [2] 63 21 [2] 74 2a [2] 6f 64 [2] 52 }

  condition:
    any of them
}