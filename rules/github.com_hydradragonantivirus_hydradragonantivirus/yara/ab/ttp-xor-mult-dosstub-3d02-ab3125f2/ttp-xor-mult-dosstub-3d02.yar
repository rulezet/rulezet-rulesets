rule TTP_XOR_MULT_DOSStub_3d02 {
  strings:
    $key_3d02 = { 69 6a [2] 1d 72 [2] 5a 70 [2] 1d 61 [2] 53 6d [2] 5f 67 [2] 48 6c [2] 53 22 [2] 6e }

  condition:
    any of them
}