rule TTP_XOR_MULT_DOSStub_3912 {
  strings:
    $key_3912 = { 6d 7a [2] 19 62 [2] 5e 60 [2] 19 71 [2] 57 7d [2] 5b 77 [2] 4c 7c [2] 57 32 [2] 6a }

  condition:
    any of them
}