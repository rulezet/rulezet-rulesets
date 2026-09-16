rule TTP_XOR_MULT_DOSStub_4529 {
  strings:
    $key_4529 = { 11 41 [2] 65 59 [2] 22 5b [2] 65 4a [2] 2b 46 [2] 27 4c [2] 30 47 [2] 2b 09 [2] 16 }

  condition:
    any of them
}