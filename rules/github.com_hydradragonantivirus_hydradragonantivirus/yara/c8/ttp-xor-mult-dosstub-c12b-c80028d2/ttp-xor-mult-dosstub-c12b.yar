rule TTP_XOR_MULT_DOSStub_c12b {
  strings:
    $key_c12b = { 95 43 [2] e1 5b [2] a6 59 [2] e1 48 [2] af 44 [2] a3 4e [2] b4 45 [2] af 0b [2] 92 }

  condition:
    any of them
}