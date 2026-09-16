rule TTP_XOR_MULT_DOSStub_fb5d {
  strings:
    $key_fb5d = { af 35 [2] db 2d [2] 9c 2f [2] db 3e [2] 95 32 [2] 99 38 [2] 8e 33 [2] 95 7d [2] a8 }

  condition:
    any of them
}