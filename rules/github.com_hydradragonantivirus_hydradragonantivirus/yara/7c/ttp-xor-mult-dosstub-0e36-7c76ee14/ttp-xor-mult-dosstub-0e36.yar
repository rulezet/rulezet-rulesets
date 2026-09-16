rule TTP_XOR_MULT_DOSStub_0e36 {
  strings:
    $key_0e36 = { 5a 5e [2] 2e 46 [2] 69 44 [2] 2e 55 [2] 60 59 [2] 6c 53 [2] 7b 58 [2] 60 16 [2] 5d }

  condition:
    any of them
}