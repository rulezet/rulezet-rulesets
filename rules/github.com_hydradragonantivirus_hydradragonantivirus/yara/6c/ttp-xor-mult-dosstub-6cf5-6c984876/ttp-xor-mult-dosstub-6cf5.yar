rule TTP_XOR_MULT_DOSStub_6cf5 {
  strings:
    $key_6cf5 = { 38 9d [2] 4c 85 [2] 0b 87 [2] 4c 96 [2] 02 9a [2] 0e 90 [2] 19 9b [2] 02 d5 [2] 3f }

  condition:
    any of them
}