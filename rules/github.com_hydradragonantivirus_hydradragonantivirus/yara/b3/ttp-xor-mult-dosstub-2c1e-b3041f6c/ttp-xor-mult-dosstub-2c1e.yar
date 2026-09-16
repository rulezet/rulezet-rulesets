rule TTP_XOR_MULT_DOSStub_2c1e {
  strings:
    $key_2c1e = { 78 76 [2] 0c 6e [2] 4b 6c [2] 0c 7d [2] 42 71 [2] 4e 7b [2] 59 70 [2] 42 3e [2] 7f }

  condition:
    any of them
}