rule TTP_XOR_MULT_DOSStub_fb4d {
  strings:
    $key_fb4d = { af 25 [2] db 3d [2] 9c 3f [2] db 2e [2] 95 22 [2] 99 28 [2] 8e 23 [2] 95 6d [2] a8 }

  condition:
    any of them
}