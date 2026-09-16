rule TTP_XOR_MULT_DOSStub_c55b {
  strings:
    $key_c55b = { 91 33 [2] e5 2b [2] a2 29 [2] e5 38 [2] ab 34 [2] a7 3e [2] b0 35 [2] ab 7b [2] 96 }

  condition:
    any of them
}