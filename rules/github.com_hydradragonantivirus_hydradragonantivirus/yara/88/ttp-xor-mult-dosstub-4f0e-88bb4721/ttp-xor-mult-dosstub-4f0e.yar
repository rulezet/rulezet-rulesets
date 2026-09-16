rule TTP_XOR_MULT_DOSStub_4f0e {
  strings:
    $key_4f0e = { 1b 66 [2] 6f 7e [2] 28 7c [2] 6f 6d [2] 21 61 [2] 2d 6b [2] 3a 60 [2] 21 2e [2] 1c }

  condition:
    any of them
}