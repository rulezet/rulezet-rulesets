rule TTP_XOR_MULT_DOSStub_05e2 {
  strings:
    $key_05e2 = { 51 8a [2] 25 92 [2] 62 90 [2] 25 81 [2] 6b 8d [2] 67 87 [2] 70 8c [2] 6b c2 [2] 56 }

  condition:
    any of them
}