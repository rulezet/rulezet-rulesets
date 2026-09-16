rule TTP_XOR_MULT_DOSStub_5a15 {
  strings:
    $key_5a15 = { 0e 7d [2] 7a 65 [2] 3d 67 [2] 7a 76 [2] 34 7a [2] 38 70 [2] 2f 7b [2] 34 35 [2] 09 }

  condition:
    any of them
}