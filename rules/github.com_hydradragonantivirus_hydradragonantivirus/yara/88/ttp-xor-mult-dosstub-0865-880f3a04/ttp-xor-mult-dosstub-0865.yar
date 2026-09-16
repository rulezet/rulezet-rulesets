rule TTP_XOR_MULT_DOSStub_0865 {
  strings:
    $key_0865 = { 5c 0d [2] 28 15 [2] 6f 17 [2] 28 06 [2] 66 0a [2] 6a 00 [2] 7d 0b [2] 66 45 [2] 5b }

  condition:
    any of them
}