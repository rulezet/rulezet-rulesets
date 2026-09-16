rule TTP_XOR_MULT_DOSStub_2f79 {
  strings:
    $key_2f79 = { 7b 11 [2] 0f 09 [2] 48 0b [2] 0f 1a [2] 41 16 [2] 4d 1c [2] 5a 17 [2] 41 59 [2] 7c }

  condition:
    any of them
}