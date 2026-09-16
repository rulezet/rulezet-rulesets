rule TTP_XOR_MULT_DOSStub_c10b {
  strings:
    $key_c10b = { 95 63 [2] e1 7b [2] a6 79 [2] e1 68 [2] af 64 [2] a3 6e [2] b4 65 [2] af 2b [2] 92 }

  condition:
    any of them
}