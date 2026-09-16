rule TTP_XOR_MULT_DOSStub_6724 {
  strings:
    $key_6724 = { 33 4c [2] 47 54 [2] 00 56 [2] 47 47 [2] 09 4b [2] 05 41 [2] 12 4a [2] 09 04 [2] 34 }

  condition:
    any of them
}