rule TTP_XOR_MULT_DOSStub_1f44 {
  strings:
    $key_1f44 = { 4b 2c [2] 3f 34 [2] 78 36 [2] 3f 27 [2] 71 2b [2] 7d 21 [2] 6a 2a [2] 71 64 [2] 4c }

  condition:
    any of them
}