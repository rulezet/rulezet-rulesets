rule TTP_XOR_MULT_DOSStub_4814 {
  strings:
    $key_4814 = { 1c 7c [2] 68 64 [2] 2f 66 [2] 68 77 [2] 26 7b [2] 2a 71 [2] 3d 7a [2] 26 34 [2] 1b }

  condition:
    any of them
}