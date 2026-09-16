rule TTP_XOR_MULT_DOSStub_fb31 {
  strings:
    $key_fb31 = { af 59 [2] db 41 [2] 9c 43 [2] db 52 [2] 95 5e [2] 99 54 [2] 8e 5f [2] 95 11 [2] a8 }

  condition:
    any of them
}