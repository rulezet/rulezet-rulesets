rule TTP_XOR_MULT_DOSStub_2d61 {
  strings:
    $key_2d61 = { 79 09 [2] 0d 11 [2] 4a 13 [2] 0d 02 [2] 43 0e [2] 4f 04 [2] 58 0f [2] 43 41 [2] 7e }

  condition:
    any of them
}