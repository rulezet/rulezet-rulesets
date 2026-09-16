rule TTP_XOR_MULT_DOSStub_39f0 {
  strings:
    $key_39f0 = { 6d 98 [2] 19 80 [2] 5e 82 [2] 19 93 [2] 57 9f [2] 5b 95 [2] 4c 9e [2] 57 d0 [2] 6a }

  condition:
    any of them
}