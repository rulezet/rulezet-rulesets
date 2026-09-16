rule TTP_XOR_MULT_DOSStub_4873 {
  strings:
    $key_4873 = { 1c 1b [2] 68 03 [2] 2f 01 [2] 68 10 [2] 26 1c [2] 2a 16 [2] 3d 1d [2] 26 53 [2] 1b }

  condition:
    any of them
}