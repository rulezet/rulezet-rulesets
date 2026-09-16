rule TTP_XOR_MULT_DOSStub_0f61 {
  strings:
    $key_0f61 = { 5b 09 [2] 2f 11 [2] 68 13 [2] 2f 02 [2] 61 0e [2] 6d 04 [2] 7a 0f [2] 61 41 [2] 5c }

  condition:
    any of them
}