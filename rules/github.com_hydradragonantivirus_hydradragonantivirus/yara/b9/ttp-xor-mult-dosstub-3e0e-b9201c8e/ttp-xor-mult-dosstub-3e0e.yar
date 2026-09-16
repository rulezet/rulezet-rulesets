rule TTP_XOR_MULT_DOSStub_3e0e {
  strings:
    $key_3e0e = { 6a 66 [2] 1e 7e [2] 59 7c [2] 1e 6d [2] 50 61 [2] 5c 6b [2] 4b 60 [2] 50 2e [2] 6d }

  condition:
    any of them
}