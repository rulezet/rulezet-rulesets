rule TTP_XOR_MULT_DOSStub_6c3f {
  strings:
    $key_6c3f = { 38 57 [2] 4c 4f [2] 0b 4d [2] 4c 5c [2] 02 50 [2] 0e 5a [2] 19 51 [2] 02 1f [2] 3f }

  condition:
    any of them
}