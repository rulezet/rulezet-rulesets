rule TTP_XOR_MULT_DOSStub_0d75 {
  strings:
    $key_0d75 = { 59 1d [2] 2d 05 [2] 6a 07 [2] 2d 16 [2] 63 1a [2] 6f 10 [2] 78 1b [2] 63 55 [2] 5e }

  condition:
    any of them
}