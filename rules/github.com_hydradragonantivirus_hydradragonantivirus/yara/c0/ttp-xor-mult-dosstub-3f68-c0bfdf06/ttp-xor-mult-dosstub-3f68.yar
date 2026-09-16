rule TTP_XOR_MULT_DOSStub_3f68 {
  strings:
    $key_3f68 = { 6b 00 [2] 1f 18 [2] 58 1a [2] 1f 0b [2] 51 07 [2] 5d 0d [2] 4a 06 [2] 51 48 [2] 6c }

  condition:
    any of them
}