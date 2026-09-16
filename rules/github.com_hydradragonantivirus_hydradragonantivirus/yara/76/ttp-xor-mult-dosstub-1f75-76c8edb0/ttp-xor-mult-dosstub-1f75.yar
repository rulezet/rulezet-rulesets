rule TTP_XOR_MULT_DOSStub_1f75 {
  strings:
    $key_1f75 = { 4b 1d [2] 3f 05 [2] 78 07 [2] 3f 16 [2] 71 1a [2] 7d 10 [2] 6a 1b [2] 71 55 [2] 4c }

  condition:
    any of them
}