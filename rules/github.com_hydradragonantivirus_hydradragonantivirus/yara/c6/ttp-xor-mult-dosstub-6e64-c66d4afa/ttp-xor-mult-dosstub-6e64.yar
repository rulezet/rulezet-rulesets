rule TTP_XOR_MULT_DOSStub_6e64 {
  strings:
    $key_6e64 = { 3a 0c [2] 4e 14 [2] 09 16 [2] 4e 07 [2] 00 0b [2] 0c 01 [2] 1b 0a [2] 00 44 [2] 3d }

  condition:
    any of them
}