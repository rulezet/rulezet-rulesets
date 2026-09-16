rule TTP_XOR_MULT_DOSStub_3de8 {
  strings:
    $key_3de8 = { 69 80 [2] 1d 98 [2] 5a 9a [2] 1d 8b [2] 53 87 [2] 5f 8d [2] 48 86 [2] 53 c8 [2] 6e }

  condition:
    any of them
}