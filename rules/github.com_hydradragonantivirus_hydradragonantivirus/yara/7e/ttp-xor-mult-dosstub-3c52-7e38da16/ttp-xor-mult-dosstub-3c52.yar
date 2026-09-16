rule TTP_XOR_MULT_DOSStub_3c52 {
  strings:
    $key_3c52 = { 68 3a [2] 1c 22 [2] 5b 20 [2] 1c 31 [2] 52 3d [2] 5e 37 [2] 49 3c [2] 52 72 [2] 6f }

  condition:
    any of them
}