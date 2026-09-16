rule TTP_XOR_MULT_DOSStub_4b07 {
  strings:
    $key_4b07 = { 1f 6f [2] 6b 77 [2] 2c 75 [2] 6b 64 [2] 25 68 [2] 29 62 [2] 3e 69 [2] 25 27 [2] 18 }

  condition:
    any of them
}