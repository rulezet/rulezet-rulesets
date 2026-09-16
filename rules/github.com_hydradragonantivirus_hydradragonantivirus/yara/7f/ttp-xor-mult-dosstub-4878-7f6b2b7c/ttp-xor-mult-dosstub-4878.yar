rule TTP_XOR_MULT_DOSStub_4878 {
  strings:
    $key_4878 = { 1c 10 [2] 68 08 [2] 2f 0a [2] 68 1b [2] 26 17 [2] 2a 1d [2] 3d 16 [2] 26 58 [2] 1b }

  condition:
    any of them
}