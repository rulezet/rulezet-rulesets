rule TTP_XOR_MULT_DOSStub_4d22 {
  strings:
    $key_4d22 = { 19 4a [2] 6d 52 [2] 2a 50 [2] 6d 41 [2] 23 4d [2] 2f 47 [2] 38 4c [2] 23 02 [2] 1e }

  condition:
    any of them
}