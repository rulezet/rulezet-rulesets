rule TTP_XOR_MULT_DOSStub_71e5 {
  strings:
    $key_71e5 = { 25 8d [2] 51 95 [2] 16 97 [2] 51 86 [2] 1f 8a [2] 13 80 [2] 04 8b [2] 1f c5 [2] 22 }

  condition:
    any of them
}