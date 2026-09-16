rule TTP_XOR_MULT_DOSStub_160e {
  strings:
    $key_160e = { 42 66 [2] 36 7e [2] 71 7c [2] 36 6d [2] 78 61 [2] 74 6b [2] 63 60 [2] 78 2e [2] 45 }

  condition:
    any of them
}