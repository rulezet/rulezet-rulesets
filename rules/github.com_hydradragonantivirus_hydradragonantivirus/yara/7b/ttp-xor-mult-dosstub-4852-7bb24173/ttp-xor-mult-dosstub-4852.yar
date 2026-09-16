rule TTP_XOR_MULT_DOSStub_4852 {
  strings:
    $key_4852 = { 1c 3a [2] 68 22 [2] 2f 20 [2] 68 31 [2] 26 3d [2] 2a 37 [2] 3d 3c [2] 26 72 [2] 1b }

  condition:
    any of them
}