rule TTP_XOR_MULT_DOSStub_5c5f {
  strings:
    $key_5c5f = { 08 37 [2] 7c 2f [2] 3b 2d [2] 7c 3c [2] 32 30 [2] 3e 3a [2] 29 31 [2] 32 7f [2] 0f }

  condition:
    any of them
}