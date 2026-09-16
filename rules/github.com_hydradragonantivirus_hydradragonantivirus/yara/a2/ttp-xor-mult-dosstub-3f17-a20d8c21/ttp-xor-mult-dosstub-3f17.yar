rule TTP_XOR_MULT_DOSStub_3f17 {
  strings:
    $key_3f17 = { 6b 7f [2] 1f 67 [2] 58 65 [2] 1f 74 [2] 51 78 [2] 5d 72 [2] 4a 79 [2] 51 37 [2] 6c }

  condition:
    any of them
}