rule TTP_XOR_MULT_DOSStub_5104 {
  strings:
    $key_5104 = { 05 6c [2] 71 74 [2] 36 76 [2] 71 67 [2] 3f 6b [2] 33 61 [2] 24 6a [2] 3f 24 [2] 02 }

  condition:
    any of them
}