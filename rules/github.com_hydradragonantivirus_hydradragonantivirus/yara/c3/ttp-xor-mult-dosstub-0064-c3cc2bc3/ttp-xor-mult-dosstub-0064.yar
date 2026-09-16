rule TTP_XOR_MULT_DOSStub_0064 {
  strings:
    $key_0064 = { 54 0c [2] 20 14 [2] 67 16 [2] 20 07 [2] 6e 0b [2] 62 01 [2] 75 0a [2] 6e 44 [2] 53 }

  condition:
    any of them
}