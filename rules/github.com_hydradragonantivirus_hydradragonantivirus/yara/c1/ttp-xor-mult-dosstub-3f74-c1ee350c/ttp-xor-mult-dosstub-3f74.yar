rule TTP_XOR_MULT_DOSStub_3f74 {
  strings:
    $key_3f74 = { 6b 1c [2] 1f 04 [2] 58 06 [2] 1f 17 [2] 51 1b [2] 5d 11 [2] 4a 1a [2] 51 54 [2] 6c }

  condition:
    any of them
}