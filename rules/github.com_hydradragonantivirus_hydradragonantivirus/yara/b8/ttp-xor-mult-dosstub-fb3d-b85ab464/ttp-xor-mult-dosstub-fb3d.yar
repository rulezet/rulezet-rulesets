rule TTP_XOR_MULT_DOSStub_fb3d {
  strings:
    $key_fb3d = { af 55 [2] db 4d [2] 9c 4f [2] db 5e [2] 95 52 [2] 99 58 [2] 8e 53 [2] 95 1d [2] a8 }

  condition:
    any of them
}