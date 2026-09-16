rule TTP_XOR_MULT_DOSStub_134e {
  strings:
    $key_134e = { 47 26 [2] 33 3e [2] 74 3c [2] 33 2d [2] 7d 21 [2] 71 2b [2] 66 20 [2] 7d 6e [2] 40 }

  condition:
    any of them
}