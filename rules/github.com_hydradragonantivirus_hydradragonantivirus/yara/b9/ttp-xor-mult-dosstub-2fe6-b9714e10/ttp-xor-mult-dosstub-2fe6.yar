rule TTP_XOR_MULT_DOSStub_2fe6 {
  strings:
    $key_2fe6 = { 7b 8e [2] 0f 96 [2] 48 94 [2] 0f 85 [2] 41 89 [2] 4d 83 [2] 5a 88 [2] 41 c6 [2] 7c }

  condition:
    any of them
}