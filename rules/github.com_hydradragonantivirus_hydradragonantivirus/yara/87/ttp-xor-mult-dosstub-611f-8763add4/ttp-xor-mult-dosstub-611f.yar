rule TTP_XOR_MULT_DOSStub_611f {
  strings:
    $key_611f = { 35 77 [2] 41 6f [2] 06 6d [2] 41 7c [2] 0f 70 [2] 03 7a [2] 14 71 [2] 0f 3f [2] 32 }

  condition:
    any of them
}