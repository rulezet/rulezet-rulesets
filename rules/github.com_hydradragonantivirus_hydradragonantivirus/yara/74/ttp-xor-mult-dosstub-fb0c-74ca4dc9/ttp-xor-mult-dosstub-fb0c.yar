rule TTP_XOR_MULT_DOSStub_fb0c {
  strings:
    $key_fb0c = { af 64 [2] db 7c [2] 9c 7e [2] db 6f [2] 95 63 [2] 99 69 [2] 8e 62 [2] 95 2c [2] a8 }

  condition:
    any of them
}