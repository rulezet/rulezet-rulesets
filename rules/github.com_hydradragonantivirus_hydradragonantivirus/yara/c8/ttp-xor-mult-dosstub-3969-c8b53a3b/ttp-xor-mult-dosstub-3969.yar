rule TTP_XOR_MULT_DOSStub_3969 {
  strings:
    $key_3969 = { 6d 01 [2] 19 19 [2] 5e 1b [2] 19 0a [2] 57 06 [2] 5b 0c [2] 4c 07 [2] 57 49 [2] 6a }

  condition:
    any of them
}