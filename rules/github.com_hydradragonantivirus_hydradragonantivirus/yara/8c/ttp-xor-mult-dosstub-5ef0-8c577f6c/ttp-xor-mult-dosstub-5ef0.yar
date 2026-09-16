rule TTP_XOR_MULT_DOSStub_5ef0 {
  strings:
    $key_5ef0 = { 0a 98 [2] 7e 80 [2] 39 82 [2] 7e 93 [2] 30 9f [2] 3c 95 [2] 2b 9e [2] 30 d0 [2] 0d }

  condition:
    any of them
}