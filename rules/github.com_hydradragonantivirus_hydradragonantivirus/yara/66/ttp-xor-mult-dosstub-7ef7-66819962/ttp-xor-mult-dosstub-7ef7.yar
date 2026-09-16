rule TTP_XOR_MULT_DOSStub_7ef7 {
  strings:
    $key_7ef7 = { 2a 9f [2] 5e 87 [2] 19 85 [2] 5e 94 [2] 10 98 [2] 1c 92 [2] 0b 99 [2] 10 d7 [2] 2d }

  condition:
    any of them
}