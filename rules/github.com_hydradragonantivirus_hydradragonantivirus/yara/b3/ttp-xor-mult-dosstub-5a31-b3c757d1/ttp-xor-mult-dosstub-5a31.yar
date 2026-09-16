rule TTP_XOR_MULT_DOSStub_5a31 {
  strings:
    $key_5a31 = { 0e 59 [2] 7a 41 [2] 3d 43 [2] 7a 52 [2] 34 5e [2] 38 54 [2] 2f 5f [2] 34 11 [2] 09 }

  condition:
    any of them
}