rule TTP_XOR_MULT_DOSStub_4de8 {
  strings:
    $key_4de8 = { 19 80 [2] 6d 98 [2] 2a 9a [2] 6d 8b [2] 23 87 [2] 2f 8d [2] 38 86 [2] 23 c8 [2] 1e }

  condition:
    any of them
}