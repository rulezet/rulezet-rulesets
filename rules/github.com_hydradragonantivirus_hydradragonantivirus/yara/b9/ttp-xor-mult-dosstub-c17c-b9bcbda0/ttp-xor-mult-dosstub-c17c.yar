rule TTP_XOR_MULT_DOSStub_c17c {
  strings:
    $key_c17c = { 95 14 [2] e1 0c [2] a6 0e [2] e1 1f [2] af 13 [2] a3 19 [2] b4 12 [2] af 5c [2] 92 }

  condition:
    any of them
}