rule TTP_XOR_MULT_DOSStub_612e {
  strings:
    $key_612e = { 35 46 [2] 41 5e [2] 06 5c [2] 41 4d [2] 0f 41 [2] 03 4b [2] 14 40 [2] 0f 0e [2] 32 }

  condition:
    any of them
}