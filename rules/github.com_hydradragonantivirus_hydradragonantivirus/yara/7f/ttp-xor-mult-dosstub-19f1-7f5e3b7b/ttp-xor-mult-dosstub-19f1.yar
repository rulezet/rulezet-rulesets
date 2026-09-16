rule TTP_XOR_MULT_DOSStub_19f1 {
  strings:
    $key_19f1 = { 4d 99 [2] 39 81 [2] 7e 83 [2] 39 92 [2] 77 9e [2] 7b 94 [2] 6c 9f [2] 77 d1 [2] 4a }

  condition:
    any of them
}