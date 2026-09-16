rule TTP_XOR_MULT_DOSStub_5d29 {
  strings:
    $key_5d29 = { 09 41 [2] 7d 59 [2] 3a 5b [2] 7d 4a [2] 33 46 [2] 3f 4c [2] 28 47 [2] 33 09 [2] 0e }

  condition:
    any of them
}