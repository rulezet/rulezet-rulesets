rule TTP_XOR_MULT_DOSStub_1f01 {
  strings:
    $key_1f01 = { 4b 69 [2] 3f 71 [2] 78 73 [2] 3f 62 [2] 71 6e [2] 7d 64 [2] 6a 6f [2] 71 21 [2] 4c }

  condition:
    any of them
}