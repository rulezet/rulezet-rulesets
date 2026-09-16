rule TTP_XOR_MULT_DOSStub_5a20 {
  strings:
    $key_5a20 = { 0e 48 [2] 7a 50 [2] 3d 52 [2] 7a 43 [2] 34 4f [2] 38 45 [2] 2f 4e [2] 34 00 [2] 09 }

  condition:
    any of them
}