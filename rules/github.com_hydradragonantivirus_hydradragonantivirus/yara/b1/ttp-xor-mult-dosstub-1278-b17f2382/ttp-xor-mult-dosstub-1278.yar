rule TTP_XOR_MULT_DOSStub_1278 {
  strings:
    $key_1278 = { 46 10 [2] 32 08 [2] 75 0a [2] 32 1b [2] 7c 17 [2] 70 1d [2] 67 16 [2] 7c 58 [2] 41 }

  condition:
    any of them
}