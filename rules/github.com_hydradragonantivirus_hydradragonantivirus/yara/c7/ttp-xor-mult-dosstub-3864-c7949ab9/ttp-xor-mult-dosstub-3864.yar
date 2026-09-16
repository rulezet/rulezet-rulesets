rule TTP_XOR_MULT_DOSStub_3864 {
  strings:
    $key_3864 = { 6c 0c [2] 18 14 [2] 5f 16 [2] 18 07 [2] 56 0b [2] 5a 01 [2] 4d 0a [2] 56 44 [2] 6b }

  condition:
    any of them
}