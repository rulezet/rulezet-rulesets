rule TTP_XOR_MULT_DOSStub_3004 {
  strings:
    $key_3004 = { 64 6c [2] 10 74 [2] 57 76 [2] 10 67 [2] 5e 6b [2] 52 61 [2] 45 6a [2] 5e 24 [2] 63 }

  condition:
    any of them
}