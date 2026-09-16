rule TTP_XOR_MULT_DOSStub_4471 {
  strings:
    $key_4471 = { 10 19 [2] 64 01 [2] 23 03 [2] 64 12 [2] 2a 1e [2] 26 14 [2] 31 1f [2] 2a 51 [2] 17 }

  condition:
    any of them
}