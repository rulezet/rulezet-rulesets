rule TTP_XOR_MULT_DOSStub_613f {
  strings:
    $key_613f = { 35 57 [2] 41 4f [2] 06 4d [2] 41 5c [2] 0f 50 [2] 03 5a [2] 14 51 [2] 0f 1f [2] 32 }

  condition:
    any of them
}