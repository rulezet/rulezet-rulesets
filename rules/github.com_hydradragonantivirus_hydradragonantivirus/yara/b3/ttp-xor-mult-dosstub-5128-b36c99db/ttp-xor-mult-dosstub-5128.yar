rule TTP_XOR_MULT_DOSStub_5128 {
  strings:
    $key_5128 = { 05 40 [2] 71 58 [2] 36 5a [2] 71 4b [2] 3f 47 [2] 33 4d [2] 24 46 [2] 3f 08 [2] 02 }

  condition:
    any of them
}