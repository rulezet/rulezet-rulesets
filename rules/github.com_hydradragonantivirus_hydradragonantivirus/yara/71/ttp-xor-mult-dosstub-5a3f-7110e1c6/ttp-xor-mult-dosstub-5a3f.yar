rule TTP_XOR_MULT_DOSStub_5a3f {
  strings:
    $key_5a3f = { 0e 57 [2] 7a 4f [2] 3d 4d [2] 7a 5c [2] 34 50 [2] 38 5a [2] 2f 51 [2] 34 1f [2] 09 }

  condition:
    any of them
}