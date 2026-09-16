rule TTP_XOR_MULT_DOSStub_4d3e {
  strings:
    $key_4d3e = { 19 56 [2] 6d 4e [2] 2a 4c [2] 6d 5d [2] 23 51 [2] 2f 5b [2] 38 50 [2] 23 1e [2] 1e }

  condition:
    any of them
}