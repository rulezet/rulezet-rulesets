rule TTP_XOR_MULT_DOSStub_6922 {
  strings:
    $key_6922 = { 3d 4a [2] 49 52 [2] 0e 50 [2] 49 41 [2] 07 4d [2] 0b 47 [2] 1c 4c [2] 07 02 [2] 3a }

  condition:
    any of them
}