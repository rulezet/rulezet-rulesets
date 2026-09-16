rule TTP_XOR_MULT_DOSStub_2029 {
  strings:
    $key_2029 = { 74 41 [2] 00 59 [2] 47 5b [2] 00 4a [2] 4e 46 [2] 42 4c [2] 55 47 [2] 4e 09 [2] 73 }

  condition:
    any of them
}