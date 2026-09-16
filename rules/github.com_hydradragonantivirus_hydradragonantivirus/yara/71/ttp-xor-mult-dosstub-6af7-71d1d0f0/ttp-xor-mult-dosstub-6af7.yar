rule TTP_XOR_MULT_DOSStub_6af7 {
  strings:
    $key_6af7 = { 3e 9f [2] 4a 87 [2] 0d 85 [2] 4a 94 [2] 04 98 [2] 08 92 [2] 1f 99 [2] 04 d7 [2] 39 }

  condition:
    any of them
}