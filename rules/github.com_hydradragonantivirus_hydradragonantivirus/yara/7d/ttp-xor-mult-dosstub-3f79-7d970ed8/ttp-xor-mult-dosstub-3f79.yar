rule TTP_XOR_MULT_DOSStub_3f79 {
  strings:
    $key_3f79 = { 6b 11 [2] 1f 09 [2] 58 0b [2] 1f 1a [2] 51 16 [2] 5d 1c [2] 4a 17 [2] 51 59 [2] 6c }

  condition:
    any of them
}