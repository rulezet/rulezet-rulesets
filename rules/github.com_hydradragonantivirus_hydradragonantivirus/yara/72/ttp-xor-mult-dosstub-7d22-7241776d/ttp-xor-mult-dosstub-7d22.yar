rule TTP_XOR_MULT_DOSStub_7d22 {
  strings:
    $key_7d22 = { 29 4a [2] 5d 52 [2] 1a 50 [2] 5d 41 [2] 13 4d [2] 1f 47 [2] 08 4c [2] 13 02 [2] 2e }

  condition:
    any of them
}