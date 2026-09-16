rule TTP_XOR_MULT_DOSStub_3d64 {
  strings:
    $key_3d64 = { 69 0c [2] 1d 14 [2] 5a 16 [2] 1d 07 [2] 53 0b [2] 5f 01 [2] 48 0a [2] 53 44 [2] 6e }

  condition:
    any of them
}