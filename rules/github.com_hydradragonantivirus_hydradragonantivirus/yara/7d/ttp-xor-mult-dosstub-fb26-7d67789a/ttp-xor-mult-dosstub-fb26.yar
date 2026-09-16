rule TTP_XOR_MULT_DOSStub_fb26 {
  strings:
    $key_fb26 = { af 4e [2] db 56 [2] 9c 54 [2] db 45 [2] 95 49 [2] 99 43 [2] 8e 48 [2] 95 06 [2] a8 }

  condition:
    any of them
}