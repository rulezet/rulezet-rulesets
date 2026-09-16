rule TTP_XOR_MULT_DOSStub_5029 {
  strings:
    $key_5029 = { 04 41 [2] 70 59 [2] 37 5b [2] 70 4a [2] 3e 46 [2] 32 4c [2] 25 47 [2] 3e 09 [2] 03 }

  condition:
    any of them
}