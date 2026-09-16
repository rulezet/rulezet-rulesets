rule TTP_XOR_MULT_DOSStub_2d33 {
  strings:
    $key_2d33 = { 79 5b [2] 0d 43 [2] 4a 41 [2] 0d 50 [2] 43 5c [2] 4f 56 [2] 58 5d [2] 43 13 [2] 7e }

  condition:
    any of them
}