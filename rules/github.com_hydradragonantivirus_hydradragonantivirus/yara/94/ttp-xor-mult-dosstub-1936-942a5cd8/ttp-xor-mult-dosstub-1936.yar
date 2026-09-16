rule TTP_XOR_MULT_DOSStub_1936 {
  strings:
    $key_1936 = { 4d 5e [2] 39 46 [2] 7e 44 [2] 39 55 [2] 77 59 [2] 7b 53 [2] 6c 58 [2] 77 16 [2] 4a }

  condition:
    any of them
}