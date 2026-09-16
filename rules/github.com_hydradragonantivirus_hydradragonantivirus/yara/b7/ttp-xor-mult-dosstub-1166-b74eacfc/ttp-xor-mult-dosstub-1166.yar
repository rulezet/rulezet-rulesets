rule TTP_XOR_MULT_DOSStub_1166 {
  strings:
    $key_1166 = { 45 0e [2] 31 16 [2] 76 14 [2] 31 05 [2] 7f 09 [2] 73 03 [2] 64 08 [2] 7f 46 [2] 42 }

  condition:
    any of them
}