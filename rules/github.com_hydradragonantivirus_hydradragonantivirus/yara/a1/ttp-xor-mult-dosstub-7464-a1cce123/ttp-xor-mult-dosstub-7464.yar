rule TTP_XOR_MULT_DOSStub_7464 {
  strings:
    $key_7464 = { 20 0c [2] 54 14 [2] 13 16 [2] 54 07 [2] 1a 0b [2] 16 01 [2] 01 0a [2] 1a 44 [2] 27 }

  condition:
    any of them
}