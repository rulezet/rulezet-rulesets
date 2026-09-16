rule TTP_XOR_MULT_DOSStub_031e {
  strings:
    $key_031e = { 57 76 [2] 23 6e [2] 64 6c [2] 23 7d [2] 6d 71 [2] 61 7b [2] 76 70 [2] 6d 3e [2] 50 }

  condition:
    any of them
}