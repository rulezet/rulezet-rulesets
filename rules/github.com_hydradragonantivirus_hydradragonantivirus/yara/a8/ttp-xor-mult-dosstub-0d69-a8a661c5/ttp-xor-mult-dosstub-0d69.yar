rule TTP_XOR_MULT_DOSStub_0d69 {
  strings:
    $key_0d69 = { 59 01 [2] 2d 19 [2] 6a 1b [2] 2d 0a [2] 63 06 [2] 6f 0c [2] 78 07 [2] 63 49 [2] 5e }

  condition:
    any of them
}