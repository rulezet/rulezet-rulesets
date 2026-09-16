rule TTP_XOR_MULT_DOSStub_5f06 {
  strings:
    $key_5f06 = { 0b 6e [2] 7f 76 [2] 38 74 [2] 7f 65 [2] 31 69 [2] 3d 63 [2] 2a 68 [2] 31 26 [2] 0c }

  condition:
    any of them
}