rule TTP_XOR_MULT_DOSStub_5ef1 {
  strings:
    $key_5ef1 = { 0a 99 [2] 7e 81 [2] 39 83 [2] 7e 92 [2] 30 9e [2] 3c 94 [2] 2b 9f [2] 30 d1 [2] 0d }

  condition:
    any of them
}