rule TTP_XOR_MULT_DOSStub_fb5c {
  strings:
    $key_fb5c = { af 34 [2] db 2c [2] 9c 2e [2] db 3f [2] 95 33 [2] 99 39 [2] 8e 32 [2] 95 7c [2] a8 }

  condition:
    any of them
}