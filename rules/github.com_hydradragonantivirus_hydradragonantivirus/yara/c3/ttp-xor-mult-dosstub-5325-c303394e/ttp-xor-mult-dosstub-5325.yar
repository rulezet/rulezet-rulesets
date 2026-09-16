rule TTP_XOR_MULT_DOSStub_5325 {
  strings:
    $key_5325 = { 07 4d [2] 73 55 [2] 34 57 [2] 73 46 [2] 3d 4a [2] 31 40 [2] 26 4b [2] 3d 05 [2] 00 }

  condition:
    any of them
}