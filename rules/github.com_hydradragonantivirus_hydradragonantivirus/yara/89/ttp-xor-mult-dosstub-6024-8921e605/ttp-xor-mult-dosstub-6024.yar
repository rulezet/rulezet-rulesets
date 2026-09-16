rule TTP_XOR_MULT_DOSStub_6024 {
  strings:
    $key_6024 = { 34 4c [2] 40 54 [2] 07 56 [2] 40 47 [2] 0e 4b [2] 02 41 [2] 15 4a [2] 0e 04 [2] 33 }

  condition:
    any of them
}