rule TTP_XOR_MULT_DOSStub_6f3f {
  strings:
    $key_6f3f = { 3b 57 [2] 4f 4f [2] 08 4d [2] 4f 5c [2] 01 50 [2] 0d 5a [2] 1a 51 [2] 01 1f [2] 3c }

  condition:
    any of them
}