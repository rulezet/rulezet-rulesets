rule TTP_XOR_MULT_DOSStub_6c29 {
  strings:
    $key_6c29 = { 38 41 [2] 4c 59 [2] 0b 5b [2] 4c 4a [2] 02 46 [2] 0e 4c [2] 19 47 [2] 02 09 [2] 3f }

  condition:
    any of them
}