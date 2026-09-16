rule TTP_XOR_MULT_DOSStub_0966 {
  strings:
    $key_0966 = { 5d 0e [2] 29 16 [2] 6e 14 [2] 29 05 [2] 67 09 [2] 6b 03 [2] 7c 08 [2] 67 46 [2] 5a }

  condition:
    any of them
}