rule TTP_XOR_MULT_DOSStub_fb52 {
  strings:
    $key_fb52 = { af 3a [2] db 22 [2] 9c 20 [2] db 31 [2] 95 3d [2] 99 37 [2] 8e 3c [2] 95 72 [2] a8 }

  condition:
    any of them
}