rule TTP_XOR_MULT_DOSStub_c33b {
  strings:
    $key_c33b = { 97 53 [2] e3 4b [2] a4 49 [2] e3 58 [2] ad 54 [2] a1 5e [2] b6 55 [2] ad 1b [2] 90 }

  condition:
    any of them
}