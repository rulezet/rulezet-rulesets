rule TTP_XOR_MULT_DOSStub_6813 {
  strings:
    $key_6813 = { 3c 7b [2] 48 63 [2] 0f 61 [2] 48 70 [2] 06 7c [2] 0a 76 [2] 1d 7d [2] 06 33 [2] 3b }

  condition:
    any of them
}