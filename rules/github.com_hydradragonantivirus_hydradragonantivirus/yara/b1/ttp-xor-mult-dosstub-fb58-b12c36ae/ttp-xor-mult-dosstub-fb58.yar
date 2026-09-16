rule TTP_XOR_MULT_DOSStub_fb58 {
  strings:
    $key_fb58 = { af 30 [2] db 28 [2] 9c 2a [2] db 3b [2] 95 37 [2] 99 3d [2] 8e 36 [2] 95 78 [2] a8 }

  condition:
    any of them
}