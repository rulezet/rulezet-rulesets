rule TTP_XOR_MULT_DOSStub_314f {
  strings:
    $key_314f = { 65 27 [2] 11 3f [2] 56 3d [2] 11 2c [2] 5f 20 [2] 53 2a [2] 44 21 [2] 5f 6f [2] 62 }

  condition:
    any of them
}