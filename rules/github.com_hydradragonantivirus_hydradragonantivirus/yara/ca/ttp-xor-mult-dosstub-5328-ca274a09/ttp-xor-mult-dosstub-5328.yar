rule TTP_XOR_MULT_DOSStub_5328 {
  strings:
    $key_5328 = { 07 40 [2] 73 58 [2] 34 5a [2] 73 4b [2] 3d 47 [2] 31 4d [2] 26 46 [2] 3d 08 [2] 00 }

  condition:
    any of them
}