rule TTP_XOR_MULT_DOSStub_0f66 {
  strings:
    $key_0f66 = { 5b 0e [2] 2f 16 [2] 68 14 [2] 2f 05 [2] 61 09 [2] 6d 03 [2] 7a 08 [2] 61 46 [2] 5c }

  condition:
    any of them
}