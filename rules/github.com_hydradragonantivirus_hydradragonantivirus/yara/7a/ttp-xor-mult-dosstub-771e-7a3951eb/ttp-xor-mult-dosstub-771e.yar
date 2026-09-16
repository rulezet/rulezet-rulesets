rule TTP_XOR_MULT_DOSStub_771e {
  strings:
    $key_771e = { 23 76 [2] 57 6e [2] 10 6c [2] 57 7d [2] 19 71 [2] 15 7b [2] 02 70 [2] 19 3e [2] 24 }

  condition:
    any of them
}