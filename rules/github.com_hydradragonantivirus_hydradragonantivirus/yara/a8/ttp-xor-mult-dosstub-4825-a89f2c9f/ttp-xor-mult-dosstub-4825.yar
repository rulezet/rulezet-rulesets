rule TTP_XOR_MULT_DOSStub_4825 {
  strings:
    $key_4825 = { 1c 4d [2] 68 55 [2] 2f 57 [2] 68 46 [2] 26 4a [2] 2a 40 [2] 3d 4b [2] 26 05 [2] 1b }

  condition:
    any of them
}