rule TTP_XOR_MULT_DOSStub_4829 {
  strings:
    $key_4829 = { 1c 41 [2] 68 59 [2] 2f 5b [2] 68 4a [2] 26 46 [2] 2a 4c [2] 3d 47 [2] 26 09 [2] 1b }

  condition:
    any of them
}