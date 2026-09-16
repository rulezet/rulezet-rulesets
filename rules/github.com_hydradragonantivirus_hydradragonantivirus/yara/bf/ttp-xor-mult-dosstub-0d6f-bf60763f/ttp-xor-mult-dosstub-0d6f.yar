rule TTP_XOR_MULT_DOSStub_0d6f {
  strings:
    $key_0d6f = { 59 07 [2] 2d 1f [2] 6a 1d [2] 2d 0c [2] 63 00 [2] 6f 0a [2] 78 01 [2] 63 4f [2] 5e }

  condition:
    any of them
}