rule TTP_XOR_MULT_DOSStub_6ee9 {
  strings:
    $key_6ee9 = { 3a 81 [2] 4e 99 [2] 09 9b [2] 4e 8a [2] 00 86 [2] 0c 8c [2] 1b 87 [2] 00 c9 [2] 3d }

  condition:
    any of them
}