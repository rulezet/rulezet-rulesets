rule TTP_XOR_MULT_DOSStub_5552 {
  strings:
    $key_5552 = { 01 3a [2] 75 22 [2] 32 20 [2] 75 31 [2] 3b 3d [2] 37 37 [2] 20 3c [2] 3b 72 [2] 06 }

  condition:
    any of them
}