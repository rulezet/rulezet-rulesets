rule TTP_XOR_MULT_DOSStub_7a71 {
  strings:
    $key_7a71 = { 2e 19 [2] 5a 01 [2] 1d 03 [2] 5a 12 [2] 14 1e [2] 18 14 [2] 0f 1f [2] 14 51 [2] 29 }

  condition:
    any of them
}