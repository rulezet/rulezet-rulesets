rule TTP_XOR_MULT_DOSStub_5c1e {
  strings:
    $key_5c1e = { 08 76 [2] 7c 6e [2] 3b 6c [2] 7c 7d [2] 32 71 [2] 3e 7b [2] 29 70 [2] 32 3e [2] 0f }

  condition:
    any of them
}