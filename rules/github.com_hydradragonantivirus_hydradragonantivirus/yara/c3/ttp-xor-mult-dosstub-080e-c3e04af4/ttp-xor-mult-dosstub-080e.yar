rule TTP_XOR_MULT_DOSStub_080e {
  strings:
    $key_080e = { 5c 66 [2] 28 7e [2] 6f 7c [2] 28 6d [2] 66 61 [2] 6a 6b [2] 7d 60 [2] 66 2e [2] 5b }

  condition:
    any of them
}