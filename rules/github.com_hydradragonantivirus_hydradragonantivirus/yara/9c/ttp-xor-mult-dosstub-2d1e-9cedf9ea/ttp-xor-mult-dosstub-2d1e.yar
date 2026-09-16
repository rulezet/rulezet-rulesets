rule TTP_XOR_MULT_DOSStub_2d1e {
  strings:
    $key_2d1e = { 79 76 [2] 0d 6e [2] 4a 6c [2] 0d 7d [2] 43 71 [2] 4f 7b [2] 58 70 [2] 43 3e [2] 7e }

  condition:
    any of them
}