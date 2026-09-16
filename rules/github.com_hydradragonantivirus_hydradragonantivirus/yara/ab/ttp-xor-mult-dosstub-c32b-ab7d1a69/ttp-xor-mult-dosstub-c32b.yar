rule TTP_XOR_MULT_DOSStub_c32b {
  strings:
    $key_c32b = { 97 43 [2] e3 5b [2] a4 59 [2] e3 48 [2] ad 44 [2] a1 4e [2] b6 45 [2] ad 0b [2] 90 }

  condition:
    any of them
}