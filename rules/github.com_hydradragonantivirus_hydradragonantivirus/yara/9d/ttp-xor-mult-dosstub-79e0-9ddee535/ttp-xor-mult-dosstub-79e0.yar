rule TTP_XOR_MULT_DOSStub_79e0 {
  strings:
    $key_79e0 = { 2d 88 [2] 59 90 [2] 1e 92 [2] 59 83 [2] 17 8f [2] 1b 85 [2] 0c 8e [2] 17 c0 [2] 2a }

  condition:
    any of them
}