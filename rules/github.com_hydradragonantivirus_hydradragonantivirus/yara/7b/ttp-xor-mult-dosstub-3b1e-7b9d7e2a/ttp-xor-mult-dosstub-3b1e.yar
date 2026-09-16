rule TTP_XOR_MULT_DOSStub_3b1e {
  strings:
    $key_3b1e = { 6f 76 [2] 1b 6e [2] 5c 6c [2] 1b 7d [2] 55 71 [2] 59 7b [2] 4e 70 [2] 55 3e [2] 68 }

  condition:
    any of them
}