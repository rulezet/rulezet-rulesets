rule TTP_XOR_MULT_DOSStub_5f17 {
  strings:
    $key_5f17 = { 0b 7f [2] 7f 67 [2] 38 65 [2] 7f 74 [2] 31 78 [2] 3d 72 [2] 2a 79 [2] 31 37 [2] 0c }

  condition:
    any of them
}