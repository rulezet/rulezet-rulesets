rule TTP_XOR_MULT_DOSStub_0f65 {
  strings:
    $key_0f65 = { 5b 0d [2] 2f 15 [2] 68 17 [2] 2f 06 [2] 61 0a [2] 6d 00 [2] 7a 0b [2] 61 45 [2] 5c }

  condition:
    any of them
}