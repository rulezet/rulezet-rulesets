rule TTP_XOR_MULT_DOSStub_631e {
  strings:
    $key_631e = { 37 76 [2] 43 6e [2] 04 6c [2] 43 7d [2] 0d 71 [2] 01 7b [2] 16 70 [2] 0d 3e [2] 30 }

  condition:
    any of them
}