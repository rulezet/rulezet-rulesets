rule TTP_XOR_MULT_DOSStub_1173 {
  strings:
    $key_1173 = { 45 1b [2] 31 03 [2] 76 01 [2] 31 10 [2] 7f 1c [2] 73 16 [2] 64 1d [2] 7f 53 [2] 42 }

  condition:
    any of them
}