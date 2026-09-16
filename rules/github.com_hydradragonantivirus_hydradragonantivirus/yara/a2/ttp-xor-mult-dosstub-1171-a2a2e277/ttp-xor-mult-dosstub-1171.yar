rule TTP_XOR_MULT_DOSStub_1171 {
  strings:
    $key_1171 = { 45 19 [2] 31 01 [2] 76 03 [2] 31 12 [2] 7f 1e [2] 73 14 [2] 64 1f [2] 7f 51 [2] 42 }

  condition:
    any of them
}