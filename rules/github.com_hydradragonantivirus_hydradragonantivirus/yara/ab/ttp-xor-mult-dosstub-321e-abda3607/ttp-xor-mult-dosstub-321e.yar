rule TTP_XOR_MULT_DOSStub_321e {
  strings:
    $key_321e = { 66 76 [2] 12 6e [2] 55 6c [2] 12 7d [2] 5c 71 [2] 50 7b [2] 47 70 [2] 5c 3e [2] 61 }

  condition:
    any of them
}