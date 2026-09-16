rule TTP_XOR_MULT_DOSStub_340e {
  strings:
    $key_340e = { 60 66 [2] 14 7e [2] 53 7c [2] 14 6d [2] 5a 61 [2] 56 6b [2] 41 60 [2] 5a 2e [2] 67 }

  condition:
    any of them
}