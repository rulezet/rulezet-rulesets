rule TTP_XOR_MULT_DOSStub_5a50 {
  strings:
    $key_5a50 = { 0e 38 [2] 7a 20 [2] 3d 22 [2] 7a 33 [2] 34 3f [2] 38 35 [2] 2f 3e [2] 34 70 [2] 09 }

  condition:
    any of them
}