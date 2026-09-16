rule TTP_XOR_MULT_DOSStub_632e {
  strings:
    $key_632e = { 37 46 [2] 43 5e [2] 04 5c [2] 43 4d [2] 0d 41 [2] 01 4b [2] 16 40 [2] 0d 0e [2] 30 }

  condition:
    any of them
}