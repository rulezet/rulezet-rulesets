rule TTP_XOR_MULT_DOSStub_38e8 {
  strings:
    $key_38e8 = { 6c 80 [2] 18 98 [2] 5f 9a [2] 18 8b [2] 56 87 [2] 5a 8d [2] 4d 86 [2] 56 c8 [2] 6b }

  condition:
    any of them
}