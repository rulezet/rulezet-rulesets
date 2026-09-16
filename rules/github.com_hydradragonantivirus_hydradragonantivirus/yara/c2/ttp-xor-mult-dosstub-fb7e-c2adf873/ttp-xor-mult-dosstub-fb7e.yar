rule TTP_XOR_MULT_DOSStub_fb7e {
  strings:
    $key_fb7e = { af 16 [2] db 0e [2] 9c 0c [2] db 1d [2] 95 11 [2] 99 1b [2] 8e 10 [2] 95 5e [2] a8 }

  condition:
    any of them
}