rule TTP_XOR_MULT_DOSStub_571e {
  strings:
    $key_571e = { 03 76 [2] 77 6e [2] 30 6c [2] 77 7d [2] 39 71 [2] 35 7b [2] 22 70 [2] 39 3e [2] 04 }

  condition:
    any of them
}