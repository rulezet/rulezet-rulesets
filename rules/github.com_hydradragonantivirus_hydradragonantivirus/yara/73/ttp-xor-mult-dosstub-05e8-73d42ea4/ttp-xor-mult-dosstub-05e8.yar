rule TTP_XOR_MULT_DOSStub_05e8 {
  strings:
    $key_05e8 = { 51 80 [2] 25 98 [2] 62 9a [2] 25 8b [2] 6b 87 [2] 67 8d [2] 70 86 [2] 6b c8 [2] 56 }

  condition:
    any of them
}