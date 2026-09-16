rule TTP_XOR_MULT_DOSStub_3916 {
  strings:
    $key_3916 = { 6d 7e [2] 19 66 [2] 5e 64 [2] 19 75 [2] 57 79 [2] 5b 73 [2] 4c 78 [2] 57 36 [2] 6a }

  condition:
    any of them
}