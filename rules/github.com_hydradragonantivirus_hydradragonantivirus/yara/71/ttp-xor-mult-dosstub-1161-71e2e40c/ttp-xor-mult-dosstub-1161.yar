rule TTP_XOR_MULT_DOSStub_1161 {
  strings:
    $key_1161 = { 45 09 [2] 31 11 [2] 76 13 [2] 31 02 [2] 7f 0e [2] 73 04 [2] 64 0f [2] 7f 41 [2] 42 }

  condition:
    any of them
}