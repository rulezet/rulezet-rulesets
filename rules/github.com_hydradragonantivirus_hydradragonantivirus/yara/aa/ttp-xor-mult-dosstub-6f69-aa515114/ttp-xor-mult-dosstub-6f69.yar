rule TTP_XOR_MULT_DOSStub_6f69 {
  strings:
    $key_6f69 = { 3b 01 [2] 4f 19 [2] 08 1b [2] 4f 0a [2] 01 06 [2] 0d 0c [2] 1a 07 [2] 01 49 [2] 3c }

  condition:
    any of them
}