rule TTP_XOR_MULT_DOSStub_6ae9 {
  strings:
    $key_6ae9 = { 3e 81 [2] 4a 99 [2] 0d 9b [2] 4a 8a [2] 04 86 [2] 08 8c [2] 1f 87 [2] 04 c9 [2] 39 }

  condition:
    any of them
}