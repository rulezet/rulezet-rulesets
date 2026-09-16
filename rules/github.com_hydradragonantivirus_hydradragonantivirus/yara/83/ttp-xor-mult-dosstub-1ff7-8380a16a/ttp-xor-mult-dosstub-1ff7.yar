rule TTP_XOR_MULT_DOSStub_1ff7 {
  strings:
    $key_1ff7 = { 4b 9f [2] 3f 87 [2] 78 85 [2] 3f 94 [2] 71 98 [2] 7d 92 [2] 6a 99 [2] 71 d7 [2] 4c }

  condition:
    any of them
}