rule TTP_XOR_MULT_DOSStub_31e8 {
  strings:
    $key_31e8 = { 65 80 [2] 11 98 [2] 56 9a [2] 11 8b [2] 5f 87 [2] 53 8d [2] 44 86 [2] 5f c8 [2] 62 }

  condition:
    any of them
}