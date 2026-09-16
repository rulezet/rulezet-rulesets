rule TTP_XOR_MULT_DOSStub_5b97 {
  strings:
    $key_5b97 = { 0f ff [2] 7b e7 [2] 3c e5 [2] 7b f4 [2] 35 f8 [2] 39 f2 [2] 2e f9 [2] 35 b7 [2] 08 }

  condition:
    any of them
}