rule TTP_XOR_MULT_DOSStub_4064 {
  strings:
    $key_4064 = { 14 0c [2] 60 14 [2] 27 16 [2] 60 07 [2] 2e 0b [2] 22 01 [2] 35 0a [2] 2e 44 [2] 13 }

  condition:
    any of them
}