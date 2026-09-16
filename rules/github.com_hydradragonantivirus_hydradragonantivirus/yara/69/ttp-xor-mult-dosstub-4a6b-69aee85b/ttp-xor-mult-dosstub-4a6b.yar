rule TTP_XOR_MULT_DOSStub_4a6b {
  strings:
    $key_4a6b = { 1e 03 [2] 6a 1b [2] 2d 19 [2] 6a 08 [2] 24 04 [2] 28 0e [2] 3f 05 [2] 24 4b [2] 19 }

  condition:
    any of them
}