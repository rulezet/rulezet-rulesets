rule TTP_XOR_MULT_DOSStub_5d3e {
  strings:
    $key_5d3e = { 09 56 [2] 7d 4e [2] 3a 4c [2] 7d 5d [2] 33 51 [2] 3f 5b [2] 28 50 [2] 33 1e [2] 0e }

  condition:
    any of them
}