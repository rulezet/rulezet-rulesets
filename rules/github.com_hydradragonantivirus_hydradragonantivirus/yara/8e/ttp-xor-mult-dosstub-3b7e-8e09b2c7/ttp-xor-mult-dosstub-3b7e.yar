rule TTP_XOR_MULT_DOSStub_3b7e {
  strings:
    $key_3b7e = { 6f 16 [2] 1b 0e [2] 5c 0c [2] 1b 1d [2] 55 11 [2] 59 1b [2] 4e 10 [2] 55 5e [2] 68 }

  condition:
    any of them
}