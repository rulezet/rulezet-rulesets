rule TTP_XOR_MULT_DOSStub_fb01 {
  strings:
    $key_fb01 = { af 69 [2] db 71 [2] 9c 73 [2] db 62 [2] 95 6e [2] 99 64 [2] 8e 6f [2] 95 21 [2] a8 }

  condition:
    any of them
}