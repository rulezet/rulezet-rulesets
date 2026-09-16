rule TTP_XOR_MULT_DOSStub_6978 {
  strings:
    $key_6978 = { 3d 10 [2] 49 08 [2] 0e 0a [2] 49 1b [2] 07 17 [2] 0b 1d [2] 1c 16 [2] 07 58 [2] 3a }

  condition:
    any of them
}