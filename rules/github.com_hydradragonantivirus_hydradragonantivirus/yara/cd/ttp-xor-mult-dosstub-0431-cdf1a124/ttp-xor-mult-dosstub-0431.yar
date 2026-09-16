rule TTP_XOR_MULT_DOSStub_0431 {
  strings:
    $key_0431 = { 50 59 [2] 24 41 [2] 63 43 [2] 24 52 [2] 6a 5e [2] 66 54 [2] 71 5f [2] 6a 11 [2] 57 }

  condition:
    any of them
}