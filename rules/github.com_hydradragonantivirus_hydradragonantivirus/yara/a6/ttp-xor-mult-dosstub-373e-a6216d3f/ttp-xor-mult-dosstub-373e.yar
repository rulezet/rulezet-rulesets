rule TTP_XOR_MULT_DOSStub_373e {
  strings:
    $key_373e = { 63 56 [2] 17 4e [2] 50 4c [2] 17 5d [2] 59 51 [2] 55 5b [2] 42 50 [2] 59 1e [2] 64 }

  condition:
    any of them
}