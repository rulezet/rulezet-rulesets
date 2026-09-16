rule TTP_XOR_MULT_DOSStub_6955 {
  strings:
    $key_6955 = { 3d 3d [2] 49 25 [2] 0e 27 [2] 49 36 [2] 07 3a [2] 0b 30 [2] 1c 3b [2] 07 75 [2] 3a }

  condition:
    any of them
}