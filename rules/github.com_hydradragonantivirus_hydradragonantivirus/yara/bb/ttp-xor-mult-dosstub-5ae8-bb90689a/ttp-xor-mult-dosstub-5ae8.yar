rule TTP_XOR_MULT_DOSStub_5ae8 {
  strings:
    $key_5ae8 = { 0e 80 [2] 7a 98 [2] 3d 9a [2] 7a 8b [2] 34 87 [2] 38 8d [2] 2f 86 [2] 34 c8 [2] 09 }

  condition:
    any of them
}