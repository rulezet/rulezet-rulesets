rule TTP_XOR_MULT_DOSStub_5f31 {
  strings:
    $key_5f31 = { 0b 59 [2] 7f 41 [2] 38 43 [2] 7f 52 [2] 31 5e [2] 3d 54 [2] 2a 5f [2] 31 11 [2] 0c }

  condition:
    any of them
}