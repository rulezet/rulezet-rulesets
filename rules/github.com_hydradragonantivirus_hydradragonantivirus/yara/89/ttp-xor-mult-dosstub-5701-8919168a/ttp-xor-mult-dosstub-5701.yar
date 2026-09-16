rule TTP_XOR_MULT_DOSStub_5701 {
  strings:
    $key_5701 = { 03 69 [2] 77 71 [2] 30 73 [2] 77 62 [2] 39 6e [2] 35 64 [2] 22 6f [2] 39 21 [2] 04 }

  condition:
    any of them
}