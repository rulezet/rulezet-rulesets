rule TTP_XOR_MULT_DOSStub_2f59 {
  strings:
    $key_2f59 = { 7b 31 [2] 0f 29 [2] 48 2b [2] 0f 3a [2] 41 36 [2] 4d 3c [2] 5a 37 [2] 41 79 [2] 7c }

  condition:
    any of them
}