rule TTP_XOR_MULT_DOSStub_616f {
  strings:
    $key_616f = { 35 07 [2] 41 1f [2] 06 1d [2] 41 0c [2] 0f 00 [2] 03 0a [2] 14 01 [2] 0f 4f [2] 32 }

  condition:
    any of them
}