rule TTP_XOR_MULT_DOSStub_551e {
  strings:
    $key_551e = { 01 76 [2] 75 6e [2] 32 6c [2] 75 7d [2] 3b 71 [2] 37 7b [2] 20 70 [2] 3b 3e [2] 06 }

  condition:
    any of them
}