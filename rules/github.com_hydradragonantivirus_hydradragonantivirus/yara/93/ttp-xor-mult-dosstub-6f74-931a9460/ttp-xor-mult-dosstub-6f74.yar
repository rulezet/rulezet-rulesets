rule TTP_XOR_MULT_DOSStub_6f74 {
  strings:
    $key_6f74 = { 3b 1c [2] 4f 04 [2] 08 06 [2] 4f 17 [2] 01 1b [2] 0d 11 [2] 1a 1a [2] 01 54 [2] 3c }

  condition:
    any of them
}