rule TTP_XOR_MULT_DOSStub_3b6e {
  strings:
    $key_3b6e = { 6f 06 [2] 1b 1e [2] 5c 1c [2] 1b 0d [2] 55 01 [2] 59 0b [2] 4e 00 [2] 55 4e [2] 68 }

  condition:
    any of them
}