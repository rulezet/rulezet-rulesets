rule TTP_XOR_MULT_DOSStub_254f {
  strings:
    $key_254f = { 71 27 [2] 05 3f [2] 42 3d [2] 05 2c [2] 4b 20 [2] 47 2a [2] 50 21 [2] 4b 6f [2] 76 }

  condition:
    any of them
}