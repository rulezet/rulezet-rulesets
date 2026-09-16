rule TTP_XOR_MULT_DOSStub_fb20 {
  strings:
    $key_fb20 = { af 48 [2] db 50 [2] 9c 52 [2] db 43 [2] 95 4f [2] 99 45 [2] 8e 4e [2] 95 00 [2] a8 }

  condition:
    any of them
}