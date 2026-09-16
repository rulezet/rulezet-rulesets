rule TTP_XOR_MULT_DOSStub_f564 {
  strings:
    $key_f564 = { a1 0c [2] d5 14 [2] 92 16 [2] d5 07 [2] 9b 0b [2] 97 01 [2] 80 0a [2] 9b 44 [2] a6 }

  condition:
    any of them
}