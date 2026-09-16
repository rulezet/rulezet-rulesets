rule TTP_XOR_MULT_DOSStub_5d11 {
  strings:
    $key_5d11 = { 09 79 [2] 7d 61 [2] 3a 63 [2] 7d 72 [2] 33 7e [2] 3f 74 [2] 28 7f [2] 33 31 [2] 0e }

  condition:
    any of them
}