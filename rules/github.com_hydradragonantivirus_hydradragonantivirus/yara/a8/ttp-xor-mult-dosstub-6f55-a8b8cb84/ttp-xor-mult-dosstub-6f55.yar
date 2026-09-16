rule TTP_XOR_MULT_DOSStub_6f55 {
  strings:
    $key_6f55 = { 3b 3d [2] 4f 25 [2] 08 27 [2] 4f 36 [2] 01 3a [2] 0d 30 [2] 1a 3b [2] 01 75 [2] 3c }

  condition:
    any of them
}