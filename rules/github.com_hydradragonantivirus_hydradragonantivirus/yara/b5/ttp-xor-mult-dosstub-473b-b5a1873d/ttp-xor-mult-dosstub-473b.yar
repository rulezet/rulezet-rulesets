rule TTP_XOR_MULT_DOSStub_473b {
  strings:
    $key_473b = { 13 53 [2] 67 4b [2] 20 49 [2] 67 58 [2] 29 54 [2] 25 5e [2] 32 55 [2] 29 1b [2] 14 }

  condition:
    any of them
}