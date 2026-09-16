rule TTP_XOR_MULT_DOSStub_5b1e {
  strings:
    $key_5b1e = { 0f 76 [2] 7b 6e [2] 3c 6c [2] 7b 7d [2] 35 71 [2] 39 7b [2] 2e 70 [2] 35 3e [2] 08 }

  condition:
    any of them
}