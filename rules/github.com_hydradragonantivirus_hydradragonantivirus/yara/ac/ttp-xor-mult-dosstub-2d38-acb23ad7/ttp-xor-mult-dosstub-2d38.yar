rule TTP_XOR_MULT_DOSStub_2d38 {
  strings:
    $key_2d38 = { 79 50 [2] 0d 48 [2] 4a 4a [2] 0d 5b [2] 43 57 [2] 4f 5d [2] 58 56 [2] 43 18 [2] 7e }

  condition:
    any of them
}