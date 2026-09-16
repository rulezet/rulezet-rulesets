rule TTP_XOR_MULT_DOSStub_1117 {
  strings:
    $key_1117 = { 45 7f [2] 31 67 [2] 76 65 [2] 31 74 [2] 7f 78 [2] 73 72 [2] 64 79 [2] 7f 37 [2] 42 }

  condition:
    any of them
}