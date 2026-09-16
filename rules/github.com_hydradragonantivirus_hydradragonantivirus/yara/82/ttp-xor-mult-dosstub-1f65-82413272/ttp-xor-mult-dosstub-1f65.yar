rule TTP_XOR_MULT_DOSStub_1f65 {
  strings:
    $key_1f65 = { 4b 0d [2] 3f 15 [2] 78 17 [2] 3f 06 [2] 71 0a [2] 7d 00 [2] 6a 0b [2] 71 45 [2] 4c }

  condition:
    any of them
}