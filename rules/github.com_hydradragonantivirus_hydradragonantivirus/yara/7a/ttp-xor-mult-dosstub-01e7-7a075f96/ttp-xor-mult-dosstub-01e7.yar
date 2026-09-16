rule TTP_XOR_MULT_DOSStub_01e7 {
  strings:
    $key_01e7 = { 55 8f [2] 21 97 [2] 66 95 [2] 21 84 [2] 6f 88 [2] 63 82 [2] 74 89 [2] 6f c7 [2] 52 }

  condition:
    any of them
}