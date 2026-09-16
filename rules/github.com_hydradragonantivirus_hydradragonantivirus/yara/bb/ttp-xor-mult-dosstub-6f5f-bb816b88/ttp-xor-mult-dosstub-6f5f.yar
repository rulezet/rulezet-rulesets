rule TTP_XOR_MULT_DOSStub_6f5f {
  strings:
    $key_6f5f = { 3b 37 [2] 4f 2f [2] 08 2d [2] 4f 3c [2] 01 30 [2] 0d 3a [2] 1a 31 [2] 01 7f [2] 3c }

  condition:
    any of them
}