rule TTP_XOR_MULT_DOSStub_1d0f {
  strings:
    $key_1d0f = { 49 67 [2] 3d 7f [2] 7a 7d [2] 3d 6c [2] 73 60 [2] 7f 6a [2] 68 61 [2] 73 2f [2] 4e }

  condition:
    any of them
}