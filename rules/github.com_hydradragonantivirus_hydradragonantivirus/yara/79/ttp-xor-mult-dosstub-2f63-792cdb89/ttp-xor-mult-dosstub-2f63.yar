rule TTP_XOR_MULT_DOSStub_2f63 {
  strings:
    $key_2f63 = { 7b 0b [2] 0f 13 [2] 48 11 [2] 0f 00 [2] 41 0c [2] 4d 06 [2] 5a 0d [2] 41 43 [2] 7c }

  condition:
    any of them
}