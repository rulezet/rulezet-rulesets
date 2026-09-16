rule TTP_XOR_MULT_DOSStub_2e4f {
  strings:
    $key_2e4f = { 7a 27 [2] 0e 3f [2] 49 3d [2] 0e 2c [2] 40 20 [2] 4c 2a [2] 5b 21 [2] 40 6f [2] 7d }

  condition:
    any of them
}