rule TTP_XOR_MULT_DOSStub_dfb8 {
  strings:
    $key_dfb8 = { 8b d0 [2] ff c8 [2] b8 ca [2] ff db [2] b1 d7 [2] bd dd [2] aa d6 [2] b1 98 [2] 8c }

  condition:
    any of them
}