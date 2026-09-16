rule TTP_XOR_MULT_DOSStub_6e24 {
  strings:
    $key_6e24 = { 3a 4c [2] 4e 54 [2] 09 56 [2] 4e 47 [2] 00 4b [2] 0c 41 [2] 1b 4a [2] 00 04 [2] 3d }

  condition:
    any of them
}