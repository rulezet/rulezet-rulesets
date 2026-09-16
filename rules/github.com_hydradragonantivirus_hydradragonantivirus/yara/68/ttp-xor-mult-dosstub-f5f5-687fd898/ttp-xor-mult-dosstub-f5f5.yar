rule TTP_XOR_MULT_DOSStub_f5f5 {
  strings:
    $key_f5f5 = { a1 9d [2] d5 85 [2] 92 87 [2] d5 96 [2] 9b 9a [2] 97 90 [2] 80 9b [2] 9b d5 [2] a6 }

  condition:
    any of them
}