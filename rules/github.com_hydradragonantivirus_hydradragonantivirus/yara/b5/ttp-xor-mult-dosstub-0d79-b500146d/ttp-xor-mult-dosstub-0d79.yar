rule TTP_XOR_MULT_DOSStub_0d79 {
  strings:
    $key_0d79 = { 59 11 [2] 2d 09 [2] 6a 0b [2] 2d 1a [2] 63 16 [2] 6f 1c [2] 78 17 [2] 63 59 [2] 5e }

  condition:
    any of them
}