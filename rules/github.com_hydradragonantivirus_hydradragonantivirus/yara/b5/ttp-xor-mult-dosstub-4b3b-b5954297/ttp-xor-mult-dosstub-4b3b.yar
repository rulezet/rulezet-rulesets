rule TTP_XOR_MULT_DOSStub_4b3b {
  strings:
    $key_4b3b = { 1f 53 [2] 6b 4b [2] 2c 49 [2] 6b 58 [2] 25 54 [2] 29 5e [2] 3e 55 [2] 25 1b [2] 18 }

  condition:
    any of them
}