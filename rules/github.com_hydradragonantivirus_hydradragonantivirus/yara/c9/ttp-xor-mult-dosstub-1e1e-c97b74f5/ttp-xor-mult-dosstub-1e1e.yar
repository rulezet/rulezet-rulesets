rule TTP_XOR_MULT_DOSStub_1e1e {
  strings:
    $key_1e1e = { 4a 76 [2] 3e 6e [2] 79 6c [2] 3e 7d [2] 70 71 [2] 7c 7b [2] 6b 70 [2] 70 3e [2] 4d }

  condition:
    any of them
}