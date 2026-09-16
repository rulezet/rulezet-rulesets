rule TTP_XOR_MULT_DOSStub_6c1f {
  strings:
    $key_6c1f = { 38 77 [2] 4c 6f [2] 0b 6d [2] 4c 7c [2] 02 70 [2] 0e 7a [2] 19 71 [2] 02 3f [2] 3f }

  condition:
    any of them
}