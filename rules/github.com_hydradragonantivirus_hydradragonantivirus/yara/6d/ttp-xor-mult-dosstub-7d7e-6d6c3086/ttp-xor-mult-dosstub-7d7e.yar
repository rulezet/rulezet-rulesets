rule TTP_XOR_MULT_DOSStub_7d7e {
  strings:
    $key_7d7e = { 29 16 [2] 5d 0e [2] 1a 0c [2] 5d 1d [2] 13 11 [2] 1f 1b [2] 08 10 [2] 13 5e [2] 2e }

  condition:
    any of them
}