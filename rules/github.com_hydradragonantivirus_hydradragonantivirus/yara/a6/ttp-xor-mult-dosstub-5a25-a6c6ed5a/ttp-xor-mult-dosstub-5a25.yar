rule TTP_XOR_MULT_DOSStub_5a25 {
  strings:
    $key_5a25 = { 0e 4d [2] 7a 55 [2] 3d 57 [2] 7a 46 [2] 34 4a [2] 38 40 [2] 2f 4b [2] 34 05 [2] 09 }

  condition:
    any of them
}