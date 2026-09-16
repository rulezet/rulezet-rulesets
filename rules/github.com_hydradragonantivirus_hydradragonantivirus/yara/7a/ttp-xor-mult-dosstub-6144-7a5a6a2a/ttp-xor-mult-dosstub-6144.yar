rule TTP_XOR_MULT_DOSStub_6144 {
  strings:
    $key_6144 = { 35 2c [2] 41 34 [2] 06 36 [2] 41 27 [2] 0f 2b [2] 03 21 [2] 14 2a [2] 0f 64 [2] 32 }

  condition:
    any of them
}