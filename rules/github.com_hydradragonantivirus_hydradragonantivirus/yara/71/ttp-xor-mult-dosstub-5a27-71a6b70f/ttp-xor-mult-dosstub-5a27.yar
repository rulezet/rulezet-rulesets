rule TTP_XOR_MULT_DOSStub_5a27 {
  strings:
    $key_5a27 = { 0e 4f [2] 7a 57 [2] 3d 55 [2] 7a 44 [2] 34 48 [2] 38 42 [2] 2f 49 [2] 34 07 [2] 09 }

  condition:
    any of them
}