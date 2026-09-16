rule TTP_XOR_MULT_DOSStub_3f63 {
  strings:
    $key_3f63 = { 6b 0b [2] 1f 13 [2] 58 11 [2] 1f 00 [2] 51 0c [2] 5d 06 [2] 4a 0d [2] 51 43 [2] 6c }

  condition:
    any of them
}