rule TTP_XOR_MULT_DOSStub_7164 {
  strings:
    $key_7164 = { 25 0c [2] 51 14 [2] 16 16 [2] 51 07 [2] 1f 0b [2] 13 01 [2] 04 0a [2] 1f 44 [2] 22 }

  condition:
    any of them
}