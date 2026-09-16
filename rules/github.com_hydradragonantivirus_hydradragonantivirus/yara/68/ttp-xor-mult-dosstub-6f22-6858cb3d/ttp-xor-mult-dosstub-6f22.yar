rule TTP_XOR_MULT_DOSStub_6f22 {
  strings:
    $key_6f22 = { 3b 4a [2] 4f 52 [2] 08 50 [2] 4f 41 [2] 01 4d [2] 0d 47 [2] 1a 4c [2] 01 02 [2] 3c }

  condition:
    any of them
}