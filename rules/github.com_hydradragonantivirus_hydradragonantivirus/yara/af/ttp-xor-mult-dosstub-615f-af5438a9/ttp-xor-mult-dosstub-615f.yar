rule TTP_XOR_MULT_DOSStub_615f {
  strings:
    $key_615f = { 35 37 [2] 41 2f [2] 06 2d [2] 41 3c [2] 0f 30 [2] 03 3a [2] 14 31 [2] 0f 7f [2] 32 }

  condition:
    any of them
}