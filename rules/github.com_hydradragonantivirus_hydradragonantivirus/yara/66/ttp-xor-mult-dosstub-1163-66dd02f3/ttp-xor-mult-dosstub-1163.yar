rule TTP_XOR_MULT_DOSStub_1163 {
  strings:
    $key_1163 = { 45 0b [2] 31 13 [2] 76 11 [2] 31 00 [2] 7f 0c [2] 73 06 [2] 64 0d [2] 7f 43 [2] 42 }

  condition:
    any of them
}