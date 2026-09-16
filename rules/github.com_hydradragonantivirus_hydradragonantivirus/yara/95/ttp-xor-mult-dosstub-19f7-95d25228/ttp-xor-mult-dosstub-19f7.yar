rule TTP_XOR_MULT_DOSStub_19f7 {
  strings:
    $key_19f7 = { 4d 9f [2] 39 87 [2] 7e 85 [2] 39 94 [2] 77 98 [2] 7b 92 [2] 6c 99 [2] 77 d7 [2] 4a }

  condition:
    any of them
}