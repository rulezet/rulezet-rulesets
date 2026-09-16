rule TTP_XOR_MULT_DOSStub_3129 {
  strings:
    $key_3129 = { 65 41 [2] 11 59 [2] 56 5b [2] 11 4a [2] 5f 46 [2] 53 4c [2] 44 47 [2] 5f 09 [2] 62 }

  condition:
    any of them
}