rule TTP_XOR_MULT_DOSStub_fb48 {
  strings:
    $key_fb48 = { af 20 [2] db 38 [2] 9c 3a [2] db 2b [2] 95 27 [2] 99 2d [2] 8e 26 [2] 95 68 [2] a8 }

  condition:
    any of them
}