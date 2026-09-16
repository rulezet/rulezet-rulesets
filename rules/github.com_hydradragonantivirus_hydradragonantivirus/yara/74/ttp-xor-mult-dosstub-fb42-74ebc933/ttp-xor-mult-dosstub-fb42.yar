rule TTP_XOR_MULT_DOSStub_fb42 {
  strings:
    $key_fb42 = { af 2a [2] db 32 [2] 9c 30 [2] db 21 [2] 95 2d [2] 99 27 [2] 8e 2c [2] 95 62 [2] a8 }

  condition:
    any of them
}