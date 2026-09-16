rule TTP_XOR_MULT_DOSStub_433b {
  strings:
    $key_433b = { 17 53 [2] 63 4b [2] 24 49 [2] 63 58 [2] 2d 54 [2] 21 5e [2] 36 55 [2] 2d 1b [2] 10 }

  condition:
    any of them
}