rule TTP_XOR_MULT_DOSStub_dfb5 {
  strings:
    $key_dfb5 = { 8b dd [2] ff c5 [2] b8 c7 [2] ff d6 [2] b1 da [2] bd d0 [2] aa db [2] b1 95 [2] 8c }

  condition:
    any of them
}