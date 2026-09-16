rule TTP_XOR_MULT_DOSStub_791e {
  strings:
    $key_791e = { 2d 76 [2] 59 6e [2] 1e 6c [2] 59 7d [2] 17 71 [2] 1b 7b [2] 0c 70 [2] 17 3e [2] 2a }

  condition:
    any of them
}