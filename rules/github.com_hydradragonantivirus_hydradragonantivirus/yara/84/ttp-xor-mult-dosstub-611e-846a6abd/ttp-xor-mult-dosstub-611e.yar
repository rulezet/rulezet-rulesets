rule TTP_XOR_MULT_DOSStub_611e {
  strings:
    $key_611e = { 35 76 [2] 41 6e [2] 06 6c [2] 41 7d [2] 0f 71 [2] 03 7b [2] 14 70 [2] 0f 3e [2] 32 }

  condition:
    any of them
}