rule TTP_XOR_MULT_DOSStub_5f63 {
  strings:
    $key_5f63 = { 0b 0b [2] 7f 13 [2] 38 11 [2] 7f 00 [2] 31 0c [2] 3d 06 [2] 2a 0d [2] 31 43 [2] 0c }

  condition:
    any of them
}