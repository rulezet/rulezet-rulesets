rule TTP_XOR_MULT_DOSStub_fb43 {
  strings:
    $key_fb43 = { af 2b [2] db 33 [2] 9c 31 [2] db 20 [2] 95 2c [2] 99 26 [2] 8e 2d [2] 95 63 [2] a8 }

  condition:
    any of them
}