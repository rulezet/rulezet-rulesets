rule TTP_XOR_MULT_DOSStub_2a01 {
  strings:
    $key_2a01 = { 7e 69 [2] 0a 71 [2] 4d 73 [2] 0a 62 [2] 44 6e [2] 48 64 [2] 5f 6f [2] 44 21 [2] 79 }

  condition:
    any of them
}