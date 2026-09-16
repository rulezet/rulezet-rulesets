rule TTP_XOR_MULT_DOSStub_1121 {
  strings:
    $key_1121 = { 45 49 [2] 31 51 [2] 76 53 [2] 31 42 [2] 7f 4e [2] 73 44 [2] 64 4f [2] 7f 01 [2] 42 }

  condition:
    any of them
}