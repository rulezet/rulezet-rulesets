rule TTP_XOR_MULT_DOSStub_2d11 {
  strings:
    $key_2d11 = { 79 79 [2] 0d 61 [2] 4a 63 [2] 0d 72 [2] 43 7e [2] 4f 74 [2] 58 7f [2] 43 31 [2] 7e }

  condition:
    any of them
}