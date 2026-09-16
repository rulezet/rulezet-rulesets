rule TTP_XOR_MULT_DOSStub_2fe4 {
  strings:
    $key_2fe4 = { 7b 8c [2] 0f 94 [2] 48 96 [2] 0f 87 [2] 41 8b [2] 4d 81 [2] 5a 8a [2] 41 c4 [2] 7c }

  condition:
    any of them
}