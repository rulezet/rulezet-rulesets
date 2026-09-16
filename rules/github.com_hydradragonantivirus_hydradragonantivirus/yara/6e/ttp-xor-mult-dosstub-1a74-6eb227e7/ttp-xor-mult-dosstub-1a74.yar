rule TTP_XOR_MULT_DOSStub_1a74 {
  strings:
    $key_1a74 = { 4e 1c [2] 3a 04 [2] 7d 06 [2] 3a 17 [2] 74 1b [2] 78 11 [2] 6f 1a [2] 74 54 [2] 49 }

  condition:
    any of them
}