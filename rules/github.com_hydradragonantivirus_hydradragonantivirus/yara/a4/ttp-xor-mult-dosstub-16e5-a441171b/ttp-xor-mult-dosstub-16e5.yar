rule TTP_XOR_MULT_DOSStub_16e5 {
  strings:
    $key_16e5 = { 42 8d [2] 36 95 [2] 71 97 [2] 36 86 [2] 78 8a [2] 74 80 [2] 63 8b [2] 78 c5 [2] 45 }

  condition:
    any of them
}