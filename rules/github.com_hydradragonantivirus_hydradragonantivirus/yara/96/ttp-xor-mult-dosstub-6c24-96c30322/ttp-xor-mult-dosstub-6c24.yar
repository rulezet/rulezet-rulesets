rule TTP_XOR_MULT_DOSStub_6c24 {
  strings:
    $key_6c24 = { 38 4c [2] 4c 54 [2] 0b 56 [2] 4c 47 [2] 02 4b [2] 0e 41 [2] 19 4a [2] 02 04 [2] 3f }

  condition:
    any of them
}