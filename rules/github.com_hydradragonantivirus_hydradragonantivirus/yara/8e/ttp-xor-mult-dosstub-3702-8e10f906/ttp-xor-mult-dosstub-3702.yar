rule TTP_XOR_MULT_DOSStub_3702 {
  strings:
    $key_3702 = { 63 6a [2] 17 72 [2] 50 70 [2] 17 61 [2] 59 6d [2] 55 67 [2] 42 6c [2] 59 22 [2] 64 }

  condition:
    any of them
}