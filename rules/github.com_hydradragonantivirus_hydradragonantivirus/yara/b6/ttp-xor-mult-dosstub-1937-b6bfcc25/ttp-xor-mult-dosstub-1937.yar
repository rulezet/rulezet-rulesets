rule TTP_XOR_MULT_DOSStub_1937 {
  strings:
    $key_1937 = { 4d 5f [2] 39 47 [2] 7e 45 [2] 39 54 [2] 77 58 [2] 7b 52 [2] 6c 59 [2] 77 17 [2] 4a }

  condition:
    any of them
}