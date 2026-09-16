rule TTP_XOR_MULT_DOSStub_5859 {
  strings:
    $key_5859 = { 0c 31 [2] 78 29 [2] 3f 2b [2] 78 3a [2] 36 36 [2] 3a 3c [2] 2d 37 [2] 36 79 [2] 0b }

  condition:
    any of them
}