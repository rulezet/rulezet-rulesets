rule TTP_XOR_MULT_DOSStub_6114 {
  strings:
    $key_6114 = { 35 7c [2] 41 64 [2] 06 66 [2] 41 77 [2] 0f 7b [2] 03 71 [2] 14 7a [2] 0f 34 [2] 32 }

  condition:
    any of them
}