rule TTP_XOR_MULT_DOSStub_0569 {
  strings:
    $key_0569 = { 51 01 [2] 25 19 [2] 62 1b [2] 25 0a [2] 6b 06 [2] 67 0c [2] 70 07 [2] 6b 49 [2] 56 }

  condition:
    any of them
}