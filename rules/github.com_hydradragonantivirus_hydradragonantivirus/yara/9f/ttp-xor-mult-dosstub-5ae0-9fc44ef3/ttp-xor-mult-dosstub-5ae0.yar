rule TTP_XOR_MULT_DOSStub_5ae0 {
  strings:
    $key_5ae0 = { 0e 88 [2] 7a 90 [2] 3d 92 [2] 7a 83 [2] 34 8f [2] 38 85 [2] 2f 8e [2] 34 c0 [2] 09 }

  condition:
    any of them
}