rule TTP_XOR_MULT_DOSStub_2fe3 {
  strings:
    $key_2fe3 = { 7b 8b [2] 0f 93 [2] 48 91 [2] 0f 80 [2] 41 8c [2] 4d 86 [2] 5a 8d [2] 41 c3 [2] 7c }

  condition:
    any of them
}