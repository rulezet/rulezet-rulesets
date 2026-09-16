rule TTP_XOR_MULT_DOSStub_5ee7 {
  strings:
    $key_5ee7 = { 0a 8f [2] 7e 97 [2] 39 95 [2] 7e 84 [2] 30 88 [2] 3c 82 [2] 2b 89 [2] 30 c7 [2] 0d }

  condition:
    any of them
}