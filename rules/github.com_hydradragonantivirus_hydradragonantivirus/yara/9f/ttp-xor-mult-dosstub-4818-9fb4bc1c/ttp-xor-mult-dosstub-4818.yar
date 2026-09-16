rule TTP_XOR_MULT_DOSStub_4818 {
  strings:
    $key_4818 = { 1c 70 [2] 68 68 [2] 2f 6a [2] 68 7b [2] 26 77 [2] 2a 7d [2] 3d 76 [2] 26 38 [2] 1b }

  condition:
    any of them
}