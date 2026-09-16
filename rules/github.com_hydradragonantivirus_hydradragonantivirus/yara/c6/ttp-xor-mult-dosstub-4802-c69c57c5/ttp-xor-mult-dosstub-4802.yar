rule TTP_XOR_MULT_DOSStub_4802 {
  strings:
    $key_4802 = { 1c 6a [2] 68 72 [2] 2f 70 [2] 68 61 [2] 26 6d [2] 2a 67 [2] 3d 6c [2] 26 22 [2] 1b }

  condition:
    any of them
}