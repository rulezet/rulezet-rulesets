rule TTP_XOR_MULT_DOSStub_6402 {
  strings:
    $key_6402 = { 30 6a [2] 44 72 [2] 03 70 [2] 44 61 [2] 0a 6d [2] 06 67 [2] 11 6c [2] 0a 22 [2] 37 }

  condition:
    any of them
}