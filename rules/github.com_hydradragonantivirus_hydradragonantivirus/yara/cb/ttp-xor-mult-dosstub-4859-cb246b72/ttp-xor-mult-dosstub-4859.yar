rule TTP_XOR_MULT_DOSStub_4859 {
  strings:
    $key_4859 = { 1c 31 [2] 68 29 [2] 2f 2b [2] 68 3a [2] 26 36 [2] 2a 3c [2] 3d 37 [2] 26 79 [2] 1b }

  condition:
    any of them
}