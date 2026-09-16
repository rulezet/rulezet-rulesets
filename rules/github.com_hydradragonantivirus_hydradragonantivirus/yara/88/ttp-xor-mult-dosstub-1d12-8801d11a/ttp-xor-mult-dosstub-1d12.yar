rule TTP_XOR_MULT_DOSStub_1d12 {
  strings:
    $key_1d12 = { 49 7a [2] 3d 62 [2] 7a 60 [2] 3d 71 [2] 73 7d [2] 7f 77 [2] 68 7c [2] 73 32 [2] 4e }

  condition:
    any of them
}