rule TTP_XOR_MULT_DOSStub_282e {
  strings:
    $key_282e = { 7c 46 [2] 08 5e [2] 4f 5c [2] 08 4d [2] 46 41 [2] 4a 4b [2] 5d 40 [2] 46 0e [2] 7b }

  condition:
    any of them
}