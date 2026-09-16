rule TTP_XOR_MULT_DOSStub_171e {
  strings:
    $key_171e = { 43 76 [2] 37 6e [2] 70 6c [2] 37 7d [2] 79 71 [2] 75 7b [2] 62 70 [2] 79 3e [2] 44 }

  condition:
    any of them
}