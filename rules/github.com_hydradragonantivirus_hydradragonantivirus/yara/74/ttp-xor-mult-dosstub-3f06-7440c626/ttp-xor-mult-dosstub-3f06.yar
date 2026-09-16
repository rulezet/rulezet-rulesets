rule TTP_XOR_MULT_DOSStub_3f06 {
  strings:
    $key_3f06 = { 6b 6e [2] 1f 76 [2] 58 74 [2] 1f 65 [2] 51 69 [2] 5d 63 [2] 4a 68 [2] 51 26 [2] 6c }

  condition:
    any of them
}