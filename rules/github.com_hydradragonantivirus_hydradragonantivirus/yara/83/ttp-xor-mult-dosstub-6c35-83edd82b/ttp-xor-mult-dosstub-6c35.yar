rule TTP_XOR_MULT_DOSStub_6c35 {
  strings:
    $key_6c35 = { 38 5d [2] 4c 45 [2] 0b 47 [2] 4c 56 [2] 02 5a [2] 0e 50 [2] 19 5b [2] 02 15 [2] 3f }

  condition:
    any of them
}