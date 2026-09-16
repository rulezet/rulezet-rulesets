rule TTP_XOR_MULT_DOSStub_5a29 {
  strings:
    $key_5a29 = { 0e 41 [2] 7a 59 [2] 3d 5b [2] 7a 4a [2] 34 46 [2] 38 4c [2] 2f 47 [2] 34 09 [2] 09 }

  condition:
    any of them
}