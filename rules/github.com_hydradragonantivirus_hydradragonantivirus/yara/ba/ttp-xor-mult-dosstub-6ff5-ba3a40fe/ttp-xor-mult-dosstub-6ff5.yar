rule TTP_XOR_MULT_DOSStub_6ff5 {
  strings:
    $key_6ff5 = { 3b 9d [2] 4f 85 [2] 08 87 [2] 4f 96 [2] 01 9a [2] 0d 90 [2] 1a 9b [2] 01 d5 [2] 3c }

  condition:
    any of them
}