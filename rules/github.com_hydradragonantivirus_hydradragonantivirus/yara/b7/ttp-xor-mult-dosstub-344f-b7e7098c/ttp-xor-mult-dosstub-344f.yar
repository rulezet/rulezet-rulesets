rule TTP_XOR_MULT_DOSStub_344f {
  strings:
    $key_344f = { 60 27 [2] 14 3f [2] 53 3d [2] 14 2c [2] 5a 20 [2] 56 2a [2] 41 21 [2] 5a 6f [2] 67 }

  condition:
    any of them
}