rule TTP_XOR_MULT_DOSStub_2638 {
  strings:
    $key_2638 = { 72 50 [2] 06 48 [2] 41 4a [2] 06 5b [2] 48 57 [2] 44 5d [2] 53 56 [2] 48 18 [2] 75 }

  condition:
    any of them
}