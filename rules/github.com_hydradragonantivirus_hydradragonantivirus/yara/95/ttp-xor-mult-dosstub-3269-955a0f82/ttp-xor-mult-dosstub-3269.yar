rule TTP_XOR_MULT_DOSStub_3269 {
  strings:
    $key_3269 = { 66 01 [2] 12 19 [2] 55 1b [2] 12 0a [2] 5c 06 [2] 50 0c [2] 47 07 [2] 5c 49 [2] 61 }

  condition:
    any of them
}