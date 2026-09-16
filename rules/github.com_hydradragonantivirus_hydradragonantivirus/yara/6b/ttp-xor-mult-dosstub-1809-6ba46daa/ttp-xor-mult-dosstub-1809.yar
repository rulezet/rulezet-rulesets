rule TTP_XOR_MULT_DOSStub_1809 {
  strings:
    $key_1809 = { 4c 61 [2] 38 79 [2] 7f 7b [2] 38 6a [2] 76 66 [2] 7a 6c [2] 6d 67 [2] 76 29 [2] 4b }

  condition:
    any of them
}