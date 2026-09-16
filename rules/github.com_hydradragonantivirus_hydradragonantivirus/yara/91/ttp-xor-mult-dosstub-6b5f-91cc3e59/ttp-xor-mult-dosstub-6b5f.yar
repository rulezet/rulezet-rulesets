rule TTP_XOR_MULT_DOSStub_6b5f {
  strings:
    $key_6b5f = { 3f 37 [2] 4b 2f [2] 0c 2d [2] 4b 3c [2] 05 30 [2] 09 3a [2] 1e 31 [2] 05 7f [2] 38 }

  condition:
    any of them
}