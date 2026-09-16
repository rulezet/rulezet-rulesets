rule TTP_XOR_MULT_DOSStub_2fe8 {
  strings:
    $key_2fe8 = { 7b 80 [2] 0f 98 [2] 48 9a [2] 0f 8b [2] 41 87 [2] 4d 8d [2] 5a 86 [2] 41 c8 [2] 7c }

  condition:
    any of them
}