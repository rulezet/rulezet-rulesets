rule TTP_XOR_MULT_DOSStub_621e {
  strings:
    $key_621e = { 36 76 [2] 42 6e [2] 05 6c [2] 42 7d [2] 0c 71 [2] 00 7b [2] 17 70 [2] 0c 3e [2] 31 }

  condition:
    any of them
}