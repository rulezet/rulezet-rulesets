rule TTP_XOR_MULT_DOSStub_4b1b {
  strings:
    $key_4b1b = { 1f 73 [2] 6b 6b [2] 2c 69 [2] 6b 78 [2] 25 74 [2] 29 7e [2] 3e 75 [2] 25 3b [2] 18 }

  condition:
    any of them
}