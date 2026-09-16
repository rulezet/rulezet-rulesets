rule TTP_XOR_MULT_DOSStub_6828 {
  strings:
    $key_6828 = { 3c 40 [2] 48 58 [2] 0f 5a [2] 48 4b [2] 06 47 [2] 0a 4d [2] 1d 46 [2] 06 08 [2] 3b }

  condition:
    any of them
}