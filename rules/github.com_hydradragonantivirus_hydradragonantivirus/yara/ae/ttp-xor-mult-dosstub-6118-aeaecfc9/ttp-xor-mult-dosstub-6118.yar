rule TTP_XOR_MULT_DOSStub_6118 {
  strings:
    $key_6118 = { 35 70 [2] 41 68 [2] 06 6a [2] 41 7b [2] 0f 77 [2] 03 7d [2] 14 76 [2] 0f 38 [2] 32 }

  condition:
    any of them
}