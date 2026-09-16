rule TTP_XOR_MULT_DOSStub_f21e {
  strings:
    $key_f21e = { a6 76 [2] d2 6e [2] 95 6c [2] d2 7d [2] 9c 71 [2] 90 7b [2] 87 70 [2] 9c 3e [2] a1 }

  condition:
    any of them
}