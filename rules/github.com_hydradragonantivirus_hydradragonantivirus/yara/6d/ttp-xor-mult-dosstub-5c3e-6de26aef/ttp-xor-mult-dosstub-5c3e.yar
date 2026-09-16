rule TTP_XOR_MULT_DOSStub_5c3e {
  strings:
    $key_5c3e = { 08 56 [2] 7c 4e [2] 3b 4c [2] 7c 5d [2] 32 51 [2] 3e 5b [2] 29 50 [2] 32 1e [2] 0f }

  condition:
    any of them
}