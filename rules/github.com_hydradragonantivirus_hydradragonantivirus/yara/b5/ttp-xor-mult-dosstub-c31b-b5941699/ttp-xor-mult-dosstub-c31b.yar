rule TTP_XOR_MULT_DOSStub_c31b {
  strings:
    $key_c31b = { 97 73 [2] e3 6b [2] a4 69 [2] e3 78 [2] ad 74 [2] a1 7e [2] b6 75 [2] ad 3b [2] 90 }

  condition:
    any of them
}