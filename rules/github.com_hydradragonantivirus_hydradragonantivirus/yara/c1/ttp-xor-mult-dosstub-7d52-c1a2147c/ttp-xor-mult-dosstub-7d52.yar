rule TTP_XOR_MULT_DOSStub_7d52 {
  strings:
    $key_7d52 = { 29 3a [2] 5d 22 [2] 1a 20 [2] 5d 31 [2] 13 3d [2] 1f 37 [2] 08 3c [2] 13 72 [2] 2e }

  condition:
    any of them
}