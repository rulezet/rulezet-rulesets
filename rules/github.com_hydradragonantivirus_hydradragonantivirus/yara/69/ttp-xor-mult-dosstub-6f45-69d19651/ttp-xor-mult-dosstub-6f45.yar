rule TTP_XOR_MULT_DOSStub_6f45 {
  strings:
    $key_6f45 = { 3b 2d [2] 4f 35 [2] 08 37 [2] 4f 26 [2] 01 2a [2] 0d 20 [2] 1a 2b [2] 01 65 [2] 3c }

  condition:
    any of them
}