rule TTP_XOR_MULT_DOSStub_6ee8 {
  strings:
    $key_6ee8 = { 3a 80 [2] 4e 98 [2] 09 9a [2] 4e 8b [2] 00 87 [2] 0c 8d [2] 1b 86 [2] 00 c8 [2] 3d }

  condition:
    any of them
}