rule TTP_XOR_MULT_DOSStub_6135 {
  strings:
    $key_6135 = { 35 5d [2] 41 45 [2] 06 47 [2] 41 56 [2] 0f 5a [2] 03 50 [2] 14 5b [2] 0f 15 [2] 32 }

  condition:
    any of them
}