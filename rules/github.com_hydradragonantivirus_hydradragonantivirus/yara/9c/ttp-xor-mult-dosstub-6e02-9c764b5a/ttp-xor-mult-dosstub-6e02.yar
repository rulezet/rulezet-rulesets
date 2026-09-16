rule TTP_XOR_MULT_DOSStub_6e02 {
  strings:
    $key_6e02 = { 3a 6a [2] 4e 72 [2] 09 70 [2] 4e 61 [2] 00 6d [2] 0c 67 [2] 1b 6c [2] 00 22 [2] 3d }

  condition:
    any of them
}