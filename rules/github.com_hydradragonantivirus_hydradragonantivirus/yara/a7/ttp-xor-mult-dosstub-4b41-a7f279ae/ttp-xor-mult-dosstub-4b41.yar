rule TTP_XOR_MULT_DOSStub_4b41 {
  strings:
    $key_4b41 = { 1f 29 [2] 6b 31 [2] 2c 33 [2] 6b 22 [2] 25 2e [2] 29 24 [2] 3e 2f [2] 25 61 [2] 18 }

  condition:
    any of them
}