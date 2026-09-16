rule TTP_XOR_MULT_DOSStub_c121 {
  strings:
    $key_c121 = { 95 49 [2] e1 51 [2] a6 53 [2] e1 42 [2] af 4e [2] a3 44 [2] b4 4f [2] af 01 [2] 92 }

  condition:
    any of them
}