rule TTP_XOR_MULT_DOSStub_61f8 {
  strings:
    $key_61f8 = { 35 90 [2] 41 88 [2] 06 8a [2] 41 9b [2] 0f 97 [2] 03 9d [2] 14 96 [2] 0f d8 [2] 32 }

  condition:
    any of them
}