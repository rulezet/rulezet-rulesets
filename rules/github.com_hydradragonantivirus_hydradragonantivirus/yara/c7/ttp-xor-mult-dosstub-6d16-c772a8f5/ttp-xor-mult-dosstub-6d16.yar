rule TTP_XOR_MULT_DOSStub_6d16 {
  strings:
    $key_6d16 = { 39 7e [2] 4d 66 [2] 0a 64 [2] 4d 75 [2] 03 79 [2] 0f 73 [2] 18 78 [2] 03 36 [2] 3e }

  condition:
    any of them
}