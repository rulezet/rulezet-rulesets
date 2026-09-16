rule TTP_XOR_MULT_DOSStub_3ef1 {
  strings:
    $key_3ef1 = { 6a 99 [2] 1e 81 [2] 59 83 [2] 1e 92 [2] 50 9e [2] 5c 94 [2] 4b 9f [2] 50 d1 [2] 6d }

  condition:
    any of them
}