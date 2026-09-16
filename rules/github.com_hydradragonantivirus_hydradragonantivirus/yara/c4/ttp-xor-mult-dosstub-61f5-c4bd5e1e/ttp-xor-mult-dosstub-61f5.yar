rule TTP_XOR_MULT_DOSStub_61f5 {
  strings:
    $key_61f5 = { 35 9d [2] 41 85 [2] 06 87 [2] 41 96 [2] 0f 9a [2] 03 90 [2] 14 9b [2] 0f d5 [2] 32 }

  condition:
    any of them
}