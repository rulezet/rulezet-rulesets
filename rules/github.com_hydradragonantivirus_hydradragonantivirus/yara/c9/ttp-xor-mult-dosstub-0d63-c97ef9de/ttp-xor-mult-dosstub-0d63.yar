rule TTP_XOR_MULT_DOSStub_0d63 {
  strings:
    $key_0d63 = { 59 0b [2] 2d 13 [2] 6a 11 [2] 2d 00 [2] 63 0c [2] 6f 06 [2] 78 0d [2] 63 43 [2] 5e }

  condition:
    any of them
}