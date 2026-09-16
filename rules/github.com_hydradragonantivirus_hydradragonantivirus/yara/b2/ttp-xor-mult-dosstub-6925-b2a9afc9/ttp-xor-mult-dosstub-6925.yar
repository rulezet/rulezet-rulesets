rule TTP_XOR_MULT_DOSStub_6925 {
  strings:
    $key_6925 = { 3d 4d [2] 49 55 [2] 0e 57 [2] 49 46 [2] 07 4a [2] 0b 40 [2] 1c 4b [2] 07 05 [2] 3a }

  condition:
    any of them
}