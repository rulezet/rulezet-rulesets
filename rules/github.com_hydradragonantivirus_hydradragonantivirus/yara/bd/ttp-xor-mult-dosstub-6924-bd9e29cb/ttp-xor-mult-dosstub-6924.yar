rule TTP_XOR_MULT_DOSStub_6924 {
  strings:
    $key_6924 = { 3d 4c [2] 49 54 [2] 0e 56 [2] 49 47 [2] 07 4b [2] 0b 41 [2] 1c 4a [2] 07 04 [2] 3a }

  condition:
    any of them
}