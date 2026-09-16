rule TTP_XOR_MULT_DOSStub_6f33 {
  strings:
    $key_6f33 = { 3b 5b [2] 4f 43 [2] 08 41 [2] 4f 50 [2] 01 5c [2] 0d 56 [2] 1a 5d [2] 01 13 [2] 3c }

  condition:
    any of them
}