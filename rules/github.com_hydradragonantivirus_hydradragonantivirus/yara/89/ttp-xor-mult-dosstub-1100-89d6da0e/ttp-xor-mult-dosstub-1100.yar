rule TTP_XOR_MULT_DOSStub_1100 {
  strings:
    $key_1100 = { 45 68 [2] 31 70 [2] 76 72 [2] 31 63 [2] 7f 6f [2] 73 65 [2] 64 6e [2] 7f 20 [2] 42 }

  condition:
    any of them
}