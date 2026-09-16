rule TTP_XOR_MULT_DOSStub_1928 {
  strings:
    $key_1928 = { 4d 40 [2] 39 58 [2] 7e 5a [2] 39 4b [2] 77 47 [2] 7b 4d [2] 6c 46 [2] 77 08 [2] 4a }

  condition:
    any of them
}