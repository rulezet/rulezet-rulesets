rule TTP_XOR_MULT_DOSStub_fb0b {
  strings:
    $key_fb0b = { af 63 [2] db 7b [2] 9c 79 [2] db 68 [2] 95 64 [2] 99 6e [2] 8e 65 [2] 95 2b [2] a8 }

  condition:
    any of them
}