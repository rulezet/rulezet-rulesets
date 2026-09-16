rule TTP_XOR_MULT_DOSStub_6859 {
  strings:
    $key_6859 = { 3c 31 [2] 48 29 [2] 0f 2b [2] 48 3a [2] 06 36 [2] 0a 3c [2] 1d 37 [2] 06 79 [2] 3b }

  condition:
    any of them
}