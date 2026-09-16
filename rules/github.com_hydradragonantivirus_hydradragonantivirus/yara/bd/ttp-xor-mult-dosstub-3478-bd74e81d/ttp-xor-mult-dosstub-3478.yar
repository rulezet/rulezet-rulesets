rule TTP_XOR_MULT_DOSStub_3478 {
  strings:
    $key_3478 = { 60 10 [2] 14 08 [2] 53 0a [2] 14 1b [2] 5a 17 [2] 56 1d [2] 41 16 [2] 5a 58 [2] 67 }

  condition:
    any of them
}