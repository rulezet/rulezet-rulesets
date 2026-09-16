rule TTP_XOR_MULT_DOSStub_014e {
  strings:
    $key_014e = { 55 26 [2] 21 3e [2] 66 3c [2] 21 2d [2] 6f 21 [2] 63 2b [2] 74 20 [2] 6f 6e [2] 52 }

  condition:
    any of them
}