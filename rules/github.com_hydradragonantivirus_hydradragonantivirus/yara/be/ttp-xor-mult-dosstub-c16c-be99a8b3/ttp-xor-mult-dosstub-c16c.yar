rule TTP_XOR_MULT_DOSStub_c16c {
  strings:
    $key_c16c = { 95 04 [2] e1 1c [2] a6 1e [2] e1 0f [2] af 03 [2] a3 09 [2] b4 02 [2] af 4c [2] 92 }

  condition:
    any of them
}