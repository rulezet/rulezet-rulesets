rule TTP_XOR_MULT_DOSStub_3002 {
  strings:
    $key_3002 = { 64 6a [2] 10 72 [2] 57 70 [2] 10 61 [2] 5e 6d [2] 52 67 [2] 45 6c [2] 5e 22 [2] 63 }

  condition:
    any of them
}