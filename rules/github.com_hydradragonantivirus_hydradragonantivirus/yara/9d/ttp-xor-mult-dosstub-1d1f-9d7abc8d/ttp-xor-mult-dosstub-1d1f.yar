rule TTP_XOR_MULT_DOSStub_1d1f {
  strings:
    $key_1d1f = { 49 77 [2] 3d 6f [2] 7a 6d [2] 3d 7c [2] 73 70 [2] 7f 7a [2] 68 71 [2] 73 3f [2] 4e }

  condition:
    any of them
}