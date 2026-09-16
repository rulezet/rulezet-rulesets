rule TTP_XOR_MULT_DOSStub_3963 {
  strings:
    $key_3963 = { 6d 0b [2] 19 13 [2] 5e 11 [2] 19 00 [2] 57 0c [2] 5b 06 [2] 4c 0d [2] 57 43 [2] 6a }

  condition:
    any of them
}