rule TTP_XOR_MULT_DOSStub_1d78 {
  strings:
    $key_1d78 = { 49 10 [2] 3d 08 [2] 7a 0a [2] 3d 1b [2] 73 17 [2] 7f 1d [2] 68 16 [2] 73 58 [2] 4e }

  condition:
    any of them
}