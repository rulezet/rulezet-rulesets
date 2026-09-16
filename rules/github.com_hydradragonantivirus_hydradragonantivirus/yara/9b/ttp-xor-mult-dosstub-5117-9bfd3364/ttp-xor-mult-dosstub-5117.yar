rule TTP_XOR_MULT_DOSStub_5117 {
  strings:
    $key_5117 = { 05 7f [2] 71 67 [2] 36 65 [2] 71 74 [2] 3f 78 [2] 33 72 [2] 24 79 [2] 3f 37 [2] 02 }

  condition:
    any of them
}