rule TTP_XOR_MULT_DOSStub_4824 {
  strings:
    $key_4824 = { 1c 4c [2] 68 54 [2] 2f 56 [2] 68 47 [2] 26 4b [2] 2a 41 [2] 3d 4a [2] 26 04 [2] 1b }

  condition:
    any of them
}