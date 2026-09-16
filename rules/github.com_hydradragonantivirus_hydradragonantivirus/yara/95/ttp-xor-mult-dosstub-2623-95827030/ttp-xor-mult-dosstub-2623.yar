rule TTP_XOR_MULT_DOSStub_2623 {
  strings:
    $key_2623 = { 72 4b [2] 06 53 [2] 41 51 [2] 06 40 [2] 48 4c [2] 44 46 [2] 53 4d [2] 48 03 [2] 75 }

  condition:
    any of them
}