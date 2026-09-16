rule TTP_XOR_MULT_DOSStub_1966 {
  strings:
    $key_1966 = { 4d 0e [2] 39 16 [2] 7e 14 [2] 39 05 [2] 77 09 [2] 7b 03 [2] 6c 08 [2] 77 46 [2] 4a }

  condition:
    any of them
}