rule TTP_XOR_MULT_DOSStub_1107 {
  strings:
    $key_1107 = { 45 6f [2] 31 77 [2] 76 75 [2] 31 64 [2] 7f 68 [2] 73 62 [2] 64 69 [2] 7f 27 [2] 42 }

  condition:
    any of them
}