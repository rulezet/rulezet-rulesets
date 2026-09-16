rule TTP_XOR_MULT_DOSStub_6112 {
  strings:
    $key_6112 = { 35 7a [2] 41 62 [2] 06 60 [2] 41 71 [2] 0f 7d [2] 03 77 [2] 14 7c [2] 0f 32 [2] 32 }

  condition:
    any of them
}