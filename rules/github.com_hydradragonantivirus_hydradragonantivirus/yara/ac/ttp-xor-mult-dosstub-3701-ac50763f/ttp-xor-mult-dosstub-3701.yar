rule TTP_XOR_MULT_DOSStub_3701 {
  strings:
    $key_3701 = { 63 69 [2] 17 71 [2] 50 73 [2] 17 62 [2] 59 6e [2] 55 64 [2] 42 6f [2] 59 21 [2] 64 }

  condition:
    any of them
}