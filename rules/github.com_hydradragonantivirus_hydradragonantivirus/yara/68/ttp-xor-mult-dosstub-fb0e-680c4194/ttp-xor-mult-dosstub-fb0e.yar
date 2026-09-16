rule TTP_XOR_MULT_DOSStub_fb0e {
  strings:
    $key_fb0e = { af 66 [2] db 7e [2] 9c 7c [2] db 6d [2] 95 61 [2] 99 6b [2] 8e 60 [2] 95 2e [2] a8 }

  condition:
    any of them
}