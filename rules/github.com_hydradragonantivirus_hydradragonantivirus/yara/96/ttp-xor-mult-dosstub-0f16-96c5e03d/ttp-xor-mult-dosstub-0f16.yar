rule TTP_XOR_MULT_DOSStub_0f16 {
  strings:
    $key_0f16 = { 5b 7e [2] 2f 66 [2] 68 64 [2] 2f 75 [2] 61 79 [2] 6d 73 [2] 7a 78 [2] 61 36 [2] 5c }

  condition:
    any of them
}