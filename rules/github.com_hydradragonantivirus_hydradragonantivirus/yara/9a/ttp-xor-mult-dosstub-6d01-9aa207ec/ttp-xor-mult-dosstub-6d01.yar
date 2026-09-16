rule TTP_XOR_MULT_DOSStub_6d01 {
  strings:
    $key_6d01 = { 39 69 [2] 4d 71 [2] 0a 73 [2] 4d 62 [2] 03 6e [2] 0f 64 [2] 18 6f [2] 03 21 [2] 3e }

  condition:
    any of them
}