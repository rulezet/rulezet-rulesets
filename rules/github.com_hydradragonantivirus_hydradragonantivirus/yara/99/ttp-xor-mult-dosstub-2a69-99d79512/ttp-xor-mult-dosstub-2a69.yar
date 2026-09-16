rule TTP_XOR_MULT_DOSStub_2a69 {
  strings:
    $key_2a69 = { 7e 01 [2] 0a 19 [2] 4d 1b [2] 0a 0a [2] 44 06 [2] 48 0c [2] 5f 07 [2] 44 49 [2] 79 }

  condition:
    any of them
}