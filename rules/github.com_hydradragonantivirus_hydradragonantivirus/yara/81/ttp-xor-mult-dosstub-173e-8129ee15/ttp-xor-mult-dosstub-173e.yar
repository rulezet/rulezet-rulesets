rule TTP_XOR_MULT_DOSStub_173e {
  strings:
    $key_173e = { 43 56 [2] 37 4e [2] 70 4c [2] 37 5d [2] 79 51 [2] 75 5b [2] 62 50 [2] 79 1e [2] 44 }

  condition:
    any of them
}