rule TTP_XOR_MULT_DOSStub_5a21 {
  strings:
    $key_5a21 = { 0e 49 [2] 7a 51 [2] 3d 53 [2] 7a 42 [2] 34 4e [2] 38 44 [2] 2f 4f [2] 34 01 [2] 09 }

  condition:
    any of them
}