rule TTP_XOR_MULT_DOSStub_041e {
  strings:
    $key_041e = { 50 76 [2] 24 6e [2] 63 6c [2] 24 7d [2] 6a 71 [2] 66 7b [2] 71 70 [2] 6a 3e [2] 57 }

  condition:
    any of them
}