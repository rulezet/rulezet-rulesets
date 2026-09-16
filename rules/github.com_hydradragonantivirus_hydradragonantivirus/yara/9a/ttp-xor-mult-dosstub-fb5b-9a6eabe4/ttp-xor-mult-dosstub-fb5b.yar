rule TTP_XOR_MULT_DOSStub_fb5b {
  strings:
    $key_fb5b = { af 33 [2] db 2b [2] 9c 29 [2] db 38 [2] 95 34 [2] 99 3e [2] 8e 35 [2] 95 7b [2] a8 }

  condition:
    any of them
}