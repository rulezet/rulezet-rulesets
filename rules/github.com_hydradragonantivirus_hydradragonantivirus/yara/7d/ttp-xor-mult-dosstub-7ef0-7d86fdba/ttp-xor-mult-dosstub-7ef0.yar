rule TTP_XOR_MULT_DOSStub_7ef0 {
  strings:
    $key_7ef0 = { 2a 98 [2] 5e 80 [2] 19 82 [2] 5e 93 [2] 10 9f [2] 1c 95 [2] 0b 9e [2] 10 d0 [2] 2d }

  condition:
    any of them
}