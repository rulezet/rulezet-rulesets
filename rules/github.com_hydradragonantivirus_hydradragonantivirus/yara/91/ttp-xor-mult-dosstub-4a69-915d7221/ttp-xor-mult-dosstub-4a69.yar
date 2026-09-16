rule TTP_XOR_MULT_DOSStub_4a69 {
  strings:
    $key_4a69 = { 1e 01 [2] 6a 19 [2] 2d 1b [2] 6a 0a [2] 24 06 [2] 28 0c [2] 3f 07 [2] 24 49 [2] 19 }

  condition:
    any of them
}