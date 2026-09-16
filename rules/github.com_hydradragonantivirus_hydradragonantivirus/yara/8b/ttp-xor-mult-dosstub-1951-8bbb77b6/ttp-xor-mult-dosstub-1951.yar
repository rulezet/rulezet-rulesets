rule TTP_XOR_MULT_DOSStub_1951 {
  strings:
    $key_1951 = { 4d 39 [2] 39 21 [2] 7e 23 [2] 39 32 [2] 77 3e [2] 7b 34 [2] 6c 3f [2] 77 71 [2] 4a }

  condition:
    any of them
}