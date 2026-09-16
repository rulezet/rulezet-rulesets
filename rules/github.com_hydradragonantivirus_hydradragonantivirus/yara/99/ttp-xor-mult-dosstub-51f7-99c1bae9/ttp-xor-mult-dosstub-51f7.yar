rule TTP_XOR_MULT_DOSStub_51f7 {
  strings:
    $key_51f7 = { 05 9f [2] 71 87 [2] 36 85 [2] 71 94 [2] 3f 98 [2] 33 92 [2] 24 99 [2] 3f d7 [2] 02 }

  condition:
    any of them
}