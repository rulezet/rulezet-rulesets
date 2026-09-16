rule TTP_XOR_MULT_DOSStub_785f {
  strings:
    $key_785f = { 2c 37 [2] 58 2f [2] 1f 2d [2] 58 3c [2] 16 30 [2] 1a 3a [2] 0d 31 [2] 16 7f [2] 2b }

  condition:
    any of them
}