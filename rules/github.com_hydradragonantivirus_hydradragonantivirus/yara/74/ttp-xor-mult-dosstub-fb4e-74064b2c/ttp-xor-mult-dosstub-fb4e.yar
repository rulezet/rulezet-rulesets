rule TTP_XOR_MULT_DOSStub_fb4e {
  strings:
    $key_fb4e = { af 26 [2] db 3e [2] 9c 3c [2] db 2d [2] 95 21 [2] 99 2b [2] 8e 20 [2] 95 6e [2] a8 }

  condition:
    any of them
}