rule TTP_XOR_MULT_DOSStub_5f27 {
  strings:
    $key_5f27 = { 0b 4f [2] 7f 57 [2] 38 55 [2] 7f 44 [2] 31 48 [2] 3d 42 [2] 2a 49 [2] 31 07 [2] 0c }

  condition:
    any of them
}