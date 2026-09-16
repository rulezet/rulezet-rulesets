rule TTP_XOR_MULT_DOSStub_3708 {
  strings:
    $key_3708 = { 63 60 [2] 17 78 [2] 50 7a [2] 17 6b [2] 59 67 [2] 55 6d [2] 42 66 [2] 59 28 [2] 64 }

  condition:
    any of them
}