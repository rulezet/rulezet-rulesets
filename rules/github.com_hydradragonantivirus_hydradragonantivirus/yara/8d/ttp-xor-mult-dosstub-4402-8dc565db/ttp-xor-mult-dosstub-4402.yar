rule TTP_XOR_MULT_DOSStub_4402 {
  strings:
    $key_4402 = { 10 6a [2] 64 72 [2] 23 70 [2] 64 61 [2] 2a 6d [2] 26 67 [2] 31 6c [2] 2a 22 [2] 17 }

  condition:
    any of them
}