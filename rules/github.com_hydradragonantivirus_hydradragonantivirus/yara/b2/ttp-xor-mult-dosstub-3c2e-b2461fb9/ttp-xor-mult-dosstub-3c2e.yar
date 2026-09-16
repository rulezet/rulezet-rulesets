rule TTP_XOR_MULT_DOSStub_3c2e {
  strings:
    $key_3c2e = { 68 46 [2] 1c 5e [2] 5b 5c [2] 1c 4d [2] 52 41 [2] 5e 4b [2] 49 40 [2] 52 0e [2] 6f }

  condition:
    any of them
}