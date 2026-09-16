rule TTP_XOR_MULT_DOSStub_130e {
  strings:
    $key_130e = { 47 66 [2] 33 7e [2] 74 7c [2] 33 6d [2] 7d 61 [2] 71 6b [2] 66 60 [2] 7d 2e [2] 40 }

  condition:
    any of them
}