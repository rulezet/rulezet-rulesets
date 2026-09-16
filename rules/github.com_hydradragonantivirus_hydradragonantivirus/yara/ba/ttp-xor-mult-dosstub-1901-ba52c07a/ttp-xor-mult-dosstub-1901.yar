rule TTP_XOR_MULT_DOSStub_1901 {
  strings:
    $key_1901 = { 4d 69 [2] 39 71 [2] 7e 73 [2] 39 62 [2] 77 6e [2] 7b 64 [2] 6c 6f [2] 77 21 [2] 4a }

  condition:
    any of them
}