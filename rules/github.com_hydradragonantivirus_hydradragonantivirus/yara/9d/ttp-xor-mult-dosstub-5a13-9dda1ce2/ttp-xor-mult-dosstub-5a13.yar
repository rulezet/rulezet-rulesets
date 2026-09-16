rule TTP_XOR_MULT_DOSStub_5a13 {
  strings:
    $key_5a13 = { 0e 7b [2] 7a 63 [2] 3d 61 [2] 7a 70 [2] 34 7c [2] 38 76 [2] 2f 7d [2] 34 33 [2] 09 }

  condition:
    any of them
}