rule TTP_XOR_MULT_DOSStub_fb4b {
  strings:
    $key_fb4b = { af 23 [2] db 3b [2] 9c 39 [2] db 28 [2] 95 24 [2] 99 2e [2] 8e 25 [2] 95 6b [2] a8 }

  condition:
    any of them
}