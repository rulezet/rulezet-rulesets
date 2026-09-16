rule TTP_XOR_MULT_DOSStub_5002 {
  strings:
    $key_5002 = { 04 6a [2] 70 72 [2] 37 70 [2] 70 61 [2] 3e 6d [2] 32 67 [2] 25 6c [2] 3e 22 [2] 03 }

  condition:
    any of them
}