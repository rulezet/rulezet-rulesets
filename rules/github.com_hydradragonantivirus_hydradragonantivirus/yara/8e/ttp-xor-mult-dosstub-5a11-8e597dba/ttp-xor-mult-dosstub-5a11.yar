rule TTP_XOR_MULT_DOSStub_5a11 {
  strings:
    $key_5a11 = { 0e 79 [2] 7a 61 [2] 3d 63 [2] 7a 72 [2] 34 7e [2] 38 74 [2] 2f 7f [2] 34 31 [2] 09 }

  condition:
    any of them
}