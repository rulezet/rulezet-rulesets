rule TTP_XOR_MULT_DOSStub_3948 {
  strings:
    $key_3948 = { 6d 20 [2] 19 38 [2] 5e 3a [2] 19 2b [2] 57 27 [2] 5b 2d [2] 4c 26 [2] 57 68 [2] 6a }

  condition:
    any of them
}