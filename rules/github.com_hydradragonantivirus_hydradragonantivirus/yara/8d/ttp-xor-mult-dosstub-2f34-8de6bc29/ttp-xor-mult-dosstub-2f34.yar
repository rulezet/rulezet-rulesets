rule TTP_XOR_MULT_DOSStub_2f34 {
  strings:
    $key_2f34 = { 7b 5c [2] 0f 44 [2] 48 46 [2] 0f 57 [2] 41 5b [2] 4d 51 [2] 5a 5a [2] 41 14 [2] 7c }

  condition:
    any of them
}