rule TTP_XOR_MULT_DOSStub_6f24 {
  strings:
    $key_6f24 = { 3b 4c [2] 4f 54 [2] 08 56 [2] 4f 47 [2] 01 4b [2] 0d 41 [2] 1a 4a [2] 01 04 [2] 3c }

  condition:
    any of them
}