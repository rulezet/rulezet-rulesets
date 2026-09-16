rule TTP_XOR_MULT_DOSStub_6324 {
  strings:
    $key_6324 = { 37 4c [2] 43 54 [2] 04 56 [2] 43 47 [2] 0d 4b [2] 01 41 [2] 16 4a [2] 0d 04 [2] 30 }

  condition:
    any of them
}