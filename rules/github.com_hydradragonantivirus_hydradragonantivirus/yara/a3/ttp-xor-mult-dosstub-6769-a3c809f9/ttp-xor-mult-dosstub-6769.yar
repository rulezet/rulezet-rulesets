rule TTP_XOR_MULT_DOSStub_6769 {
  strings:
    $key_6769 = { 33 01 [2] 47 19 [2] 00 1b [2] 47 0a [2] 09 06 [2] 05 0c [2] 12 07 [2] 09 49 [2] 34 }

  condition:
    any of them
}