rule TTP_XOR_MULT_DOSStub_5f78 {
  strings:
    $key_5f78 = { 0b 10 [2] 7f 08 [2] 38 0a [2] 7f 1b [2] 31 17 [2] 3d 1d [2] 2a 16 [2] 31 58 [2] 0c }

  condition:
    any of them
}