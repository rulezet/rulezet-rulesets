rule TTP_XOR_MULT_DOSStub_3779 {
  strings:
    $key_3779 = { 63 11 [2] 17 09 [2] 50 0b [2] 17 1a [2] 59 16 [2] 55 1c [2] 42 17 [2] 59 59 [2] 64 }

  condition:
    any of them
}