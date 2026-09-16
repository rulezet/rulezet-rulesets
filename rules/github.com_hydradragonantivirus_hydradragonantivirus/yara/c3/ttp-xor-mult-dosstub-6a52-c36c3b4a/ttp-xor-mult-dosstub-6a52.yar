rule TTP_XOR_MULT_DOSStub_6a52 {
  strings:
    $key_6a52 = { 3e 3a [2] 4a 22 [2] 0d 20 [2] 4a 31 [2] 04 3d [2] 08 37 [2] 1f 3c [2] 04 72 [2] 39 }

  condition:
    any of them
}