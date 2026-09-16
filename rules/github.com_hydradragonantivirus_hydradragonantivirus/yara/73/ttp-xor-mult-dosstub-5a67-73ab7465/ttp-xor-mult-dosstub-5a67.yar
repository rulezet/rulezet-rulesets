rule TTP_XOR_MULT_DOSStub_5a67 {
  strings:
    $key_5a67 = { 0e 0f [2] 7a 17 [2] 3d 15 [2] 7a 04 [2] 34 08 [2] 38 02 [2] 2f 09 [2] 34 47 [2] 09 }

  condition:
    any of them
}