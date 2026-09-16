rule TTP_XOR_MULT_DOSStub_7e50 {
  strings:
    $key_7e50 = { 2a 38 [2] 5e 20 [2] 19 22 [2] 5e 33 [2] 10 3f [2] 1c 35 [2] 0b 3e [2] 10 70 [2] 2d }

  condition:
    any of them
}