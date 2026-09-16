rule TTP_XOR_MULT_DOSStub_6e55 {
  strings:
    $key_6e55 = { 3a 3d [2] 4e 25 [2] 09 27 [2] 4e 36 [2] 00 3a [2] 0c 30 [2] 1b 3b [2] 00 75 [2] 3d }

  condition:
    any of them
}