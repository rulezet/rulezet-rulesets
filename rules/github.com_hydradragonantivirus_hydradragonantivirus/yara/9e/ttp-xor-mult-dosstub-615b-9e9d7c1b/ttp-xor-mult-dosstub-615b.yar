rule TTP_XOR_MULT_DOSStub_615b {
  strings:
    $key_615b = { 35 33 [2] 41 2b [2] 06 29 [2] 41 38 [2] 0f 34 [2] 03 3e [2] 14 35 [2] 0f 7b [2] 32 }

  condition:
    any of them
}