rule TTP_XOR_MULT_DOSStub_3f70 {
  strings:
    $key_3f70 = { 6b 18 [2] 1f 00 [2] 58 02 [2] 1f 13 [2] 51 1f [2] 5d 15 [2] 4a 1e [2] 51 50 [2] 6c }

  condition:
    any of them
}