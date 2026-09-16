rule TTP_XOR_MULT_DOSStub_1970 {
  strings:
    $key_1970 = { 4d 18 [2] 39 00 [2] 7e 02 [2] 39 13 [2] 77 1f [2] 7b 15 [2] 6c 1e [2] 77 50 [2] 4a }

  condition:
    any of them
}