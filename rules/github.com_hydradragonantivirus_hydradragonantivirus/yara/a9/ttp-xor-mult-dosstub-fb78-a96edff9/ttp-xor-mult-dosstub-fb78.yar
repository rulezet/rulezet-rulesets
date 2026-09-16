rule TTP_XOR_MULT_DOSStub_fb78 {
  strings:
    $key_fb78 = { af 10 [2] db 08 [2] 9c 0a [2] db 1b [2] 95 17 [2] 99 1d [2] 8e 16 [2] 95 58 [2] a8 }

  condition:
    any of them
}