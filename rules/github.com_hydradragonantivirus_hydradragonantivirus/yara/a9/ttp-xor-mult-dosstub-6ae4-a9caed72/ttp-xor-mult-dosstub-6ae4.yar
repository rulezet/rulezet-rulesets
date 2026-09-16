rule TTP_XOR_MULT_DOSStub_6ae4 {
  strings:
    $key_6ae4 = { 3e 8c [2] 4a 94 [2] 0d 96 [2] 4a 87 [2] 04 8b [2] 08 81 [2] 1f 8a [2] 04 c4 [2] 39 }

  condition:
    any of them
}