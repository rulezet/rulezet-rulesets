rule TTP_XOR_MULT_DOSStub_0d64 {
  strings:
    $key_0d64 = { 59 0c [2] 2d 14 [2] 6a 16 [2] 2d 07 [2] 63 0b [2] 6f 01 [2] 78 0a [2] 63 44 [2] 5e }

  condition:
    any of them
}