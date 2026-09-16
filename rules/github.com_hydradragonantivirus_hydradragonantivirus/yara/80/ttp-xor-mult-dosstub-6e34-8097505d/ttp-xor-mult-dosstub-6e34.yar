rule TTP_XOR_MULT_DOSStub_6e34 {
  strings:
    $key_6e34 = { 3a 5c [2] 4e 44 [2] 09 46 [2] 4e 57 [2] 00 5b [2] 0c 51 [2] 1b 5a [2] 00 14 [2] 3d }

  condition:
    any of them
}