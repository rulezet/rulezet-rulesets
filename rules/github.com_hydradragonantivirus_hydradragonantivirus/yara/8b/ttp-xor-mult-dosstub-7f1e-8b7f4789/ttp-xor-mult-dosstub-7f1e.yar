rule TTP_XOR_MULT_DOSStub_7f1e {
  strings:
    $key_7f1e = { 2b 76 [2] 5f 6e [2] 18 6c [2] 5f 7d [2] 11 71 [2] 1d 7b [2] 0a 70 [2] 11 3e [2] 2c }

  condition:
    any of them
}