rule TTP_XOR_MULT_DOSStub_4b21 {
  strings:
    $key_4b21 = { 1f 49 [2] 6b 51 [2] 2c 53 [2] 6b 42 [2] 25 4e [2] 29 44 [2] 3e 4f [2] 25 01 [2] 18 }

  condition:
    any of them
}