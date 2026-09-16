rule TTP_XOR_MULT_DOSStub_226f {
  strings:
    $key_226f = { 76 07 [2] 02 1f [2] 45 1d [2] 02 0c [2] 4c 00 [2] 40 0a [2] 57 01 [2] 4c 4f [2] 71 }

  condition:
    any of them
}