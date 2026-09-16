rule TTP_XOR_MULT_DOSStub_19f0 {
  strings:
    $key_19f0 = { 4d 98 [2] 39 80 [2] 7e 82 [2] 39 93 [2] 77 9f [2] 7b 95 [2] 6c 9e [2] 77 d0 [2] 4a }

  condition:
    any of them
}