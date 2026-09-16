rule TTP_XOR_MULT_DOSStub_fb36 {
  strings:
    $key_fb36 = { af 5e [2] db 46 [2] 9c 44 [2] db 55 [2] 95 59 [2] 99 53 [2] 8e 58 [2] 95 16 [2] a8 }

  condition:
    any of them
}