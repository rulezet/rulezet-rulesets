rule TTP_XOR_MULT_DOSStub_2c1f {
  strings:
    $key_2c1f = { 78 77 [2] 0c 6f [2] 4b 6d [2] 0c 7c [2] 42 70 [2] 4e 7a [2] 59 71 [2] 42 3f [2] 7f }

  condition:
    any of them
}