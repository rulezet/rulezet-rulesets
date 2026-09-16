rule TTP_XOR_MULT_DOSStub_5f11 {
  strings:
    $key_5f11 = { 0b 79 [2] 7f 61 [2] 38 63 [2] 7f 72 [2] 31 7e [2] 3d 74 [2] 2a 7f [2] 31 31 [2] 0c }

  condition:
    any of them
}