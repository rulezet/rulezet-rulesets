rule TTP_XOR_MULT_DOSStub_1d18 {
  strings:
    $key_1d18 = { 49 70 [2] 3d 68 [2] 7a 6a [2] 3d 7b [2] 73 77 [2] 7f 7d [2] 68 76 [2] 73 38 [2] 4e }

  condition:
    any of them
}