rule TTP_XOR_MULT_DOSStub_4835 {
  strings:
    $key_4835 = { 1c 5d [2] 68 45 [2] 2f 47 [2] 68 56 [2] 26 5a [2] 2a 50 [2] 3d 5b [2] 26 15 [2] 1b }

  condition:
    any of them
}