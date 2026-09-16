rule TTP_XOR_MULT_DOSStub_4a73 {
  strings:
    $key_4a73 = { 1e 1b [2] 6a 03 [2] 2d 01 [2] 6a 10 [2] 24 1c [2] 28 16 [2] 3f 1d [2] 24 53 [2] 19 }

  condition:
    any of them
}