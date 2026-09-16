rule TTP_XOR_MULT_DOSStub_1d13 {
  strings:
    $key_1d13 = { 49 7b [2] 3d 63 [2] 7a 61 [2] 3d 70 [2] 73 7c [2] 7f 76 [2] 68 7d [2] 73 33 [2] 4e }

  condition:
    any of them
}