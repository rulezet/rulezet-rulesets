rule TTP_XOR_MULT_DOSStub_3208 {
  strings:
    $key_3208 = { 66 60 [2] 12 78 [2] 55 7a [2] 12 6b [2] 5c 67 [2] 50 6d [2] 47 66 [2] 5c 28 [2] 61 }

  condition:
    any of them
}