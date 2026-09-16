rule TTP_XOR_MULT_DOSStub_7a3b {
  strings:
    $key_7a3b = { 2e 53 [2] 5a 4b [2] 1d 49 [2] 5a 58 [2] 14 54 [2] 18 5e [2] 0f 55 [2] 14 1b [2] 29 }

  condition:
    any of them
}