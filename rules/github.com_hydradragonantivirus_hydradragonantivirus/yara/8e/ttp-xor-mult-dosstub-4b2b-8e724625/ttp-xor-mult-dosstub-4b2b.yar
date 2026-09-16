rule TTP_XOR_MULT_DOSStub_4b2b {
  strings:
    $key_4b2b = { 1f 43 [2] 6b 5b [2] 2c 59 [2] 6b 48 [2] 25 44 [2] 29 4e [2] 3e 45 [2] 25 0b [2] 18 }

  condition:
    any of them
}