rule TTP_XOR_MULT_DOSStub_5e30 {
  strings:
    $key_5e30 = { 0a 58 [2] 7e 40 [2] 39 42 [2] 7e 53 [2] 30 5f [2] 3c 55 [2] 2b 5e [2] 30 10 [2] 0d }

  condition:
    any of them
}