rule TTP_XOR_MULT_DOSStub_4b1e {
  strings:
    $key_4b1e = { 1f 76 [2] 6b 6e [2] 2c 6c [2] 6b 7d [2] 25 71 [2] 29 7b [2] 3e 70 [2] 25 3e [2] 18 }

  condition:
    any of them
}