rule TTP_XOR_MULT_DOSStub_1971 {
  strings:
    $key_1971 = { 4d 19 [2] 39 01 [2] 7e 03 [2] 39 12 [2] 77 1e [2] 7b 14 [2] 6c 1f [2] 77 51 [2] 4a }

  condition:
    any of them
}