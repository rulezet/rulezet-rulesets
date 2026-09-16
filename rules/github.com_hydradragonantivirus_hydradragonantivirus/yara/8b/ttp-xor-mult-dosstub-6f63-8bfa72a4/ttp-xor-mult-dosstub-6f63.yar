rule TTP_XOR_MULT_DOSStub_6f63 {
  strings:
    $key_6f63 = { 3b 0b [2] 4f 13 [2] 08 11 [2] 4f 00 [2] 01 0c [2] 0d 06 [2] 1a 0d [2] 01 43 [2] 3c }

  condition:
    any of them
}