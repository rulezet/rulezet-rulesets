rule TTP_XOR_MULT_DOSStub_2f65 {
  strings:
    $key_2f65 = { 7b 0d [2] 0f 15 [2] 48 17 [2] 0f 06 [2] 41 0a [2] 4d 00 [2] 5a 0b [2] 41 45 [2] 7c }

  condition:
    any of them
}