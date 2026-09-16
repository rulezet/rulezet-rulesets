rule TTP_XOR_MULT_DOSStub_0801 {
  strings:
    $key_0801 = { 5c 69 [2] 28 71 [2] 6f 73 [2] 28 62 [2] 66 6e [2] 6a 64 [2] 7d 6f [2] 66 21 [2] 5b }

  condition:
    any of them
}