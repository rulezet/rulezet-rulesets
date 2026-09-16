rule TTP_XOR_MULT_DOSStub_2b7e {
  strings:
    $key_2b7e = { 7f 16 [2] 0b 0e [2] 4c 0c [2] 0b 1d [2] 45 11 [2] 49 1b [2] 5e 10 [2] 45 5e [2] 78 }

  condition:
    any of them
}