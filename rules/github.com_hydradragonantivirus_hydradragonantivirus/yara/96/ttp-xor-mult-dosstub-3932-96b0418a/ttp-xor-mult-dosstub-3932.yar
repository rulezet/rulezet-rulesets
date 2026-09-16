rule TTP_XOR_MULT_DOSStub_3932 {
  strings:
    $key_3932 = { 6d 5a [2] 19 42 [2] 5e 40 [2] 19 51 [2] 57 5d [2] 5b 57 [2] 4c 5c [2] 57 12 [2] 6a }

  condition:
    any of them
}