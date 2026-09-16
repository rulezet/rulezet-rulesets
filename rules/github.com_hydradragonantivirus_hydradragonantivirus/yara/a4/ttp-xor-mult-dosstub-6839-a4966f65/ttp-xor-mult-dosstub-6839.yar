rule TTP_XOR_MULT_DOSStub_6839 {
  strings:
    $key_6839 = { 3c 51 [2] 48 49 [2] 0f 4b [2] 48 5a [2] 06 56 [2] 0a 5c [2] 1d 57 [2] 06 19 [2] 3b }

  condition:
    any of them
}