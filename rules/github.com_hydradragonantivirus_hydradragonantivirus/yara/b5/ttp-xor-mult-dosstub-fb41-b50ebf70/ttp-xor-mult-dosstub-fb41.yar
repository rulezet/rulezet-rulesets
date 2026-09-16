rule TTP_XOR_MULT_DOSStub_fb41 {
  strings:
    $key_fb41 = { af 29 [2] db 31 [2] 9c 33 [2] db 22 [2] 95 2e [2] 99 24 [2] 8e 2f [2] 95 61 [2] a8 }

  condition:
    any of them
}