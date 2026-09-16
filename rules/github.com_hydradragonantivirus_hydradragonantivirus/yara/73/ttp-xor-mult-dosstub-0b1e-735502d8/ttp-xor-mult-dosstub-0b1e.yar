rule TTP_XOR_MULT_DOSStub_0b1e {
  strings:
    $key_0b1e = { 5f 76 [2] 2b 6e [2] 6c 6c [2] 2b 7d [2] 65 71 [2] 69 7b [2] 7e 70 [2] 65 3e [2] 58 }

  condition:
    any of them
}