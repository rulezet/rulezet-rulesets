rule TTP_XOR_MULT_DOSStub_5e65 {
  strings:
    $key_5e65 = { 0a 0d [2] 7e 15 [2] 39 17 [2] 7e 06 [2] 30 0a [2] 3c 00 [2] 2b 0b [2] 30 45 [2] 0d }

  condition:
    any of them
}