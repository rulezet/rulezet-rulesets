rule TTP_XOR_MULT_DOSStub_05f5 {
  strings:
    $key_05f5 = { 51 9d [2] 25 85 [2] 62 87 [2] 25 96 [2] 6b 9a [2] 67 90 [2] 70 9b [2] 6b d5 [2] 56 }

  condition:
    any of them
}