rule TTP_XOR_MULT_DOSStub_3f55 {
  strings:
    $key_3f55 = { 6b 3d [2] 1f 25 [2] 58 27 [2] 1f 36 [2] 51 3a [2] 5d 30 [2] 4a 3b [2] 51 75 [2] 6c }

  condition:
    any of them
}