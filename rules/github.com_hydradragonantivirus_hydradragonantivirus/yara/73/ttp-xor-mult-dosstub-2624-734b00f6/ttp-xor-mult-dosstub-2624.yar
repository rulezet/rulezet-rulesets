rule TTP_XOR_MULT_DOSStub_2624 {
  strings:
    $key_2624 = { 72 4c [2] 06 54 [2] 41 56 [2] 06 47 [2] 48 4b [2] 44 41 [2] 53 4a [2] 48 04 [2] 75 }

  condition:
    any of them
}