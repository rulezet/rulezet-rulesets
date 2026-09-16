rule TTP_XOR_MULT_DOSStub_1e37 {
  strings:
    $key_1e37 = { 4a 5f [2] 3e 47 [2] 79 45 [2] 3e 54 [2] 70 58 [2] 7c 52 [2] 6b 59 [2] 70 17 [2] 4d }

  condition:
    any of them
}