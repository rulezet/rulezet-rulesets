rule TTP_XOR_MULT_DOSStub_0324 {
  strings:
    $key_0324 = { 57 4c [2] 23 54 [2] 64 56 [2] 23 47 [2] 6d 4b [2] 61 41 [2] 76 4a [2] 6d 04 [2] 50 }

  condition:
    any of them
}