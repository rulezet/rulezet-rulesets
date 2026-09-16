rule TTP_XOR_MULT_DOSStub_3725 {
  strings:
    $key_3725 = { 63 4d [2] 17 55 [2] 50 57 [2] 17 46 [2] 59 4a [2] 55 40 [2] 42 4b [2] 59 05 [2] 64 }

  condition:
    any of them
}