rule TTP_XOR_MULT_DOSStub_086f {
  strings:
    $key_086f = { 5c 07 [2] 28 1f [2] 6f 1d [2] 28 0c [2] 66 00 [2] 6a 0a [2] 7d 01 [2] 66 4f [2] 5b }

  condition:
    any of them
}