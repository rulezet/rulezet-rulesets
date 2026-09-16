rule TTP_XOR_MULT_DOSStub_1d23 {
  strings:
    $key_1d23 = { 49 4b [2] 3d 53 [2] 7a 51 [2] 3d 40 [2] 73 4c [2] 7f 46 [2] 68 4d [2] 73 03 [2] 4e }

  condition:
    any of them
}