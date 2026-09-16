rule TTP_XOR_MULT_DOSStub_5f47 {
  strings:
    $key_5f47 = { 0b 2f [2] 7f 37 [2] 38 35 [2] 7f 24 [2] 31 28 [2] 3d 22 [2] 2a 29 [2] 31 67 [2] 0c }

  condition:
    any of them
}