rule TTP_XOR_MULT_DOSStub_3ff7 {
  strings:
    $key_3ff7 = { 6b 9f [2] 1f 87 [2] 58 85 [2] 1f 94 [2] 51 98 [2] 5d 92 [2] 4a 99 [2] 51 d7 [2] 6c }

  condition:
    any of them
}