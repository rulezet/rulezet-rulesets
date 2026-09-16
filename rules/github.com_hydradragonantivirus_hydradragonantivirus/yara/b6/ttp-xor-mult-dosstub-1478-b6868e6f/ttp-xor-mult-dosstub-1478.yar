rule TTP_XOR_MULT_DOSStub_1478 {
  strings:
    $key_1478 = { 40 10 [2] 34 08 [2] 73 0a [2] 34 1b [2] 7a 17 [2] 76 1d [2] 61 16 [2] 7a 58 [2] 47 }

  condition:
    any of them
}