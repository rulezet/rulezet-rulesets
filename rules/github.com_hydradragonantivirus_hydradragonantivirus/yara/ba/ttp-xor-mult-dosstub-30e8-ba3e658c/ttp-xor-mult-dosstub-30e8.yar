rule TTP_XOR_MULT_DOSStub_30e8 {
  strings:
    $key_30e8 = { 64 80 [2] 10 98 [2] 57 9a [2] 10 8b [2] 5e 87 [2] 52 8d [2] 45 86 [2] 5e c8 [2] 63 }

  condition:
    any of them
}