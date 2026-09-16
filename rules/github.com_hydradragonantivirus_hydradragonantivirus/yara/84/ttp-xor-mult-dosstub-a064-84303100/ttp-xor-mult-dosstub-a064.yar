rule TTP_XOR_MULT_DOSStub_a064 {
  strings:
    $key_a064 = { f4 0c [2] 80 14 [2] c7 16 [2] 80 07 [2] ce 0b [2] c2 01 [2] d5 0a [2] ce 44 [2] f3 }

  condition:
    any of them
}