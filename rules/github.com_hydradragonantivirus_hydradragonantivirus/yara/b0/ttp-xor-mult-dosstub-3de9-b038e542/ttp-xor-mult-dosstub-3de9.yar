rule TTP_XOR_MULT_DOSStub_3de9 {
  strings:
    $key_3de9 = { 69 81 [2] 1d 99 [2] 5a 9b [2] 1d 8a [2] 53 86 [2] 5f 8c [2] 48 87 [2] 53 c9 [2] 6e }

  condition:
    any of them
}