rule TTP_XOR_MULT_DOSStub_2625 {
  strings:
    $key_2625 = { 72 4d [2] 06 55 [2] 41 57 [2] 06 46 [2] 48 4a [2] 44 40 [2] 53 4b [2] 48 05 [2] 75 }

  condition:
    any of them
}