rule TTP_XOR_MULT_DOSStub_fb37 {
  strings:
    $key_fb37 = { af 5f [2] db 47 [2] 9c 45 [2] db 54 [2] 95 58 [2] 99 52 [2] 8e 59 [2] 95 17 [2] a8 }

  condition:
    any of them
}