rule TTP_XOR_MULT_DOSStub_6923 {
  strings:
    $key_6923 = { 3d 4b [2] 49 53 [2] 0e 51 [2] 49 40 [2] 07 4c [2] 0b 46 [2] 1c 4d [2] 07 03 [2] 3a }

  condition:
    any of them
}