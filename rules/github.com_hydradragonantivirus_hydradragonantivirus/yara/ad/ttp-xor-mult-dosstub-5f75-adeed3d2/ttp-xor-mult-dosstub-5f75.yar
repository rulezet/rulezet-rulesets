rule TTP_XOR_MULT_DOSStub_5f75 {
  strings:
    $key_5f75 = { 0b 1d [2] 7f 05 [2] 38 07 [2] 7f 16 [2] 31 1a [2] 3d 10 [2] 2a 1b [2] 31 55 [2] 0c }

  condition:
    any of them
}