rule TTP_XOR_MULT_DOSStub_fb4f {
  strings:
    $key_fb4f = { af 27 [2] db 3f [2] 9c 3d [2] db 2c [2] 95 20 [2] 99 2a [2] 8e 21 [2] 95 6f [2] a8 }

  condition:
    any of them
}