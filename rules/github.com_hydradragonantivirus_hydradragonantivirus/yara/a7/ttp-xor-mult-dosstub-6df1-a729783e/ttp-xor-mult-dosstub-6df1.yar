rule TTP_XOR_MULT_DOSStub_6df1 {
  strings:
    $key_6df1 = { 39 99 [2] 4d 81 [2] 0a 83 [2] 4d 92 [2] 03 9e [2] 0f 94 [2] 18 9f [2] 03 d1 [2] 3e }

  condition:
    any of them
}