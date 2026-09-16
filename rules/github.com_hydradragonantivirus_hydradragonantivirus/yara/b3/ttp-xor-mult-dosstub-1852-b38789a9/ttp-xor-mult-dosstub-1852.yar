rule TTP_XOR_MULT_DOSStub_1852 {
  strings:
    $key_1852 = { 4c 3a [2] 38 22 [2] 7f 20 [2] 38 31 [2] 76 3d [2] 7a 37 [2] 6d 3c [2] 76 72 [2] 4b }

  condition:
    any of them
}