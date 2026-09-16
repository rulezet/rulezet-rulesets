rule TTP_XOR_MULT_DOSStub_6329 {
  strings:
    $key_6329 = { 37 41 [2] 43 59 [2] 04 5b [2] 43 4a [2] 0d 46 [2] 01 4c [2] 16 47 [2] 0d 09 [2] 30 }

  condition:
    any of them
}