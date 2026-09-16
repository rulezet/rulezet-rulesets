rule TTP_XOR_MULT_DOSStub_c63b {
  strings:
    $key_c63b = { 92 53 [2] e6 4b [2] a1 49 [2] e6 58 [2] a8 54 [2] a4 5e [2] b3 55 [2] a8 1b [2] 95 }

  condition:
    any of them
}