rule TTP_XOR_MULT_DOSStub_1f7e {
  strings:
    $key_1f7e = { 4b 16 [2] 3f 0e [2] 78 0c [2] 3f 1d [2] 71 11 [2] 7d 1b [2] 6a 10 [2] 71 5e [2] 4c }

  condition:
    any of them
}