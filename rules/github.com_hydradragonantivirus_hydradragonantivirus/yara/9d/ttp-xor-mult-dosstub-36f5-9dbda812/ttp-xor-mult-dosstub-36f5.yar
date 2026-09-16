rule TTP_XOR_MULT_DOSStub_36f5 {
  strings:
    $key_36f5 = { 62 9d [2] 16 85 [2] 51 87 [2] 16 96 [2] 58 9a [2] 54 90 [2] 43 9b [2] 58 d5 [2] 65 }

  condition:
    any of them
}