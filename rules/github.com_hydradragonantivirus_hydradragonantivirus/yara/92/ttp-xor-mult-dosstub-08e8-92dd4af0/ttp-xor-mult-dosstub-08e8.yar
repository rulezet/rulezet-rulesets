rule TTP_XOR_MULT_DOSStub_08e8 {
  strings:
    $key_08e8 = { 5c 80 [2] 28 98 [2] 6f 9a [2] 28 8b [2] 66 87 [2] 6a 8d [2] 7d 86 [2] 66 c8 [2] 5b }

  condition:
    any of them
}