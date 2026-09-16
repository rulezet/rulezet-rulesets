rule TTP_XOR_MULT_DOSStub_013e {
  strings:
    $key_013e = { 55 56 [2] 21 4e [2] 66 4c [2] 21 5d [2] 6f 51 [2] 63 5b [2] 74 50 [2] 6f 1e [2] 52 }

  condition:
    any of them
}