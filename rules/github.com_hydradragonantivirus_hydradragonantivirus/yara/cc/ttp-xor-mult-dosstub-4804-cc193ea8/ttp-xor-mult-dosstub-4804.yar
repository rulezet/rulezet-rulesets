rule TTP_XOR_MULT_DOSStub_4804 {
  strings:
    $key_4804 = { 1c 6c [2] 68 74 [2] 2f 76 [2] 68 67 [2] 26 6b [2] 2a 61 [2] 3d 6a [2] 26 24 [2] 1b }

  condition:
    any of them
}