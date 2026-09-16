rule TTP_XOR_MULT_DOSStub_1c1e {
  strings:
    $key_1c1e = { 48 76 [2] 3c 6e [2] 7b 6c [2] 3c 7d [2] 72 71 [2] 7e 7b [2] 69 70 [2] 72 3e [2] 4f }

  condition:
    any of them
}