rule TTP_XOR_MULT_DOSStub_5f74 {
  strings:
    $key_5f74 = { 0b 1c [2] 7f 04 [2] 38 06 [2] 7f 17 [2] 31 1b [2] 3d 11 [2] 2a 1a [2] 31 54 [2] 0c }

  condition:
    any of them
}