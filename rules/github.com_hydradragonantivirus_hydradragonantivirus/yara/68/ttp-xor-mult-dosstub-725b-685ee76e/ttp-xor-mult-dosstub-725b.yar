rule TTP_XOR_MULT_DOSStub_725b {
  strings:
    $key_725b = { 26 33 [2] 52 2b [2] 15 29 [2] 52 38 [2] 1c 34 [2] 10 3e [2] 07 35 [2] 1c 7b [2] 21 }

  condition:
    any of them
}