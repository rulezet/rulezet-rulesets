rule TTP_XOR_MULT_DOSStub_5162 {
  strings:
    $key_5162 = { 05 0a [2] 71 12 [2] 36 10 [2] 71 01 [2] 3f 0d [2] 33 07 [2] 24 0c [2] 3f 42 [2] 02 }

  condition:
    any of them
}