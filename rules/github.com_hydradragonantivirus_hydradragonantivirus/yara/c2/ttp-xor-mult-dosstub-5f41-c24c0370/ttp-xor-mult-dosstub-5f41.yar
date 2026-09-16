rule TTP_XOR_MULT_DOSStub_5f41 {
  strings:
    $key_5f41 = { 0b 29 [2] 7f 31 [2] 38 33 [2] 7f 22 [2] 31 2e [2] 3d 24 [2] 2a 2f [2] 31 61 [2] 0c }

  condition:
    any of them
}