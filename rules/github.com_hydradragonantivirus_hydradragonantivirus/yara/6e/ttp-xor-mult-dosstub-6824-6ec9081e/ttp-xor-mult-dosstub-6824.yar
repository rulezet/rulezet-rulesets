rule TTP_XOR_MULT_DOSStub_6824 {
  strings:
    $key_6824 = { 3c 4c [2] 48 54 [2] 0f 56 [2] 48 47 [2] 06 4b [2] 0a 41 [2] 1d 4a [2] 06 04 [2] 3b }

  condition:
    any of them
}