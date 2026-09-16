rule TTP_XOR_MULT_DOSStub_460c {
  strings:
    $key_460c = { 12 64 [2] 66 7c [2] 21 7e [2] 66 6f [2] 28 63 [2] 24 69 [2] 33 62 [2] 28 2c [2] 15 }

  condition:
    any of them
}