rule TTP_XOR_MULT_DOSStub_0f79 {
  strings:
    $key_0f79 = { 5b 11 [2] 2f 09 [2] 68 0b [2] 2f 1a [2] 61 16 [2] 6d 1c [2] 7a 17 [2] 61 59 [2] 5c }

  condition:
    any of them
}