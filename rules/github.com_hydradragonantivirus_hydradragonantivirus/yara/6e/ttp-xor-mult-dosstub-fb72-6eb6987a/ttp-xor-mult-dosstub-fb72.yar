rule TTP_XOR_MULT_DOSStub_fb72 {
  strings:
    $key_fb72 = { af 1a [2] db 02 [2] 9c 00 [2] db 11 [2] 95 1d [2] 99 17 [2] 8e 1c [2] 95 52 [2] a8 }

  condition:
    any of them
}