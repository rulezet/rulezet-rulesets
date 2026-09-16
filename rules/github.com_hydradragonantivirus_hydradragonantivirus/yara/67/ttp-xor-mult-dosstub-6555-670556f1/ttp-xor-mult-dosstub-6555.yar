rule TTP_XOR_MULT_DOSStub_6555 {
  strings:
    $key_6555 = { 31 3d [2] 45 25 [2] 02 27 [2] 45 36 [2] 0b 3a [2] 07 30 [2] 10 3b [2] 0b 75 [2] 36 }

  condition:
    any of them
}