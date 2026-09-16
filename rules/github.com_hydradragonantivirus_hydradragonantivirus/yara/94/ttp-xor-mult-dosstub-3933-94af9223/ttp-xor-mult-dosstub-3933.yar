rule TTP_XOR_MULT_DOSStub_3933 {
  strings:
    $key_3933 = { 6d 5b [2] 19 43 [2] 5e 41 [2] 19 50 [2] 57 5c [2] 5b 56 [2] 4c 5d [2] 57 13 [2] 6a }

  condition:
    any of them
}