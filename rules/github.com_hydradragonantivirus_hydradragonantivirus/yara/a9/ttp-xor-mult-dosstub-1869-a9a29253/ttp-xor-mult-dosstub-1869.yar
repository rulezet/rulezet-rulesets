rule TTP_XOR_MULT_DOSStub_1869 {
  strings:
    $key_1869 = { 4c 01 [2] 38 19 [2] 7f 1b [2] 38 0a [2] 76 06 [2] 7a 0c [2] 6d 07 [2] 76 49 [2] 4b }

  condition:
    any of them
}