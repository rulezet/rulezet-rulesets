rule TTP_XOR_MULT_DOSStub_274f {
  strings:
    $key_274f = { 73 27 [2] 07 3f [2] 40 3d [2] 07 2c [2] 49 20 [2] 45 2a [2] 52 21 [2] 49 6f [2] 74 }

  condition:
    any of them
}