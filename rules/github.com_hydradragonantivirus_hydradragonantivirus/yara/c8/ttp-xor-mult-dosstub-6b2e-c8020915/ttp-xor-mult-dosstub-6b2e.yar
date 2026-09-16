rule TTP_XOR_MULT_DOSStub_6b2e {
  strings:
    $key_6b2e = { 3f 46 [2] 4b 5e [2] 0c 5c [2] 4b 4d [2] 05 41 [2] 09 4b [2] 1e 40 [2] 05 0e [2] 38 }

  condition:
    any of them
}