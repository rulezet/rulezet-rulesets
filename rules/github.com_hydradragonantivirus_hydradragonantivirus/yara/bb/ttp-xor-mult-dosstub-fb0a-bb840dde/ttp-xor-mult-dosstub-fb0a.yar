rule TTP_XOR_MULT_DOSStub_fb0a {
  strings:
    $key_fb0a = { af 62 [2] db 7a [2] 9c 78 [2] db 69 [2] 95 65 [2] 99 6f [2] 8e 64 [2] 95 2a [2] a8 }

  condition:
    any of them
}