rule TTP_XOR_MULT_DOSStub_684f {
  strings:
    $key_684f = { 3c 27 [2] 48 3f [2] 0f 3d [2] 48 2c [2] 06 20 [2] 0a 2a [2] 1d 21 [2] 06 6f [2] 3b }

  condition:
    any of them
}