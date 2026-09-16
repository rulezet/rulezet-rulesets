rule TTP_XOR_MULT_DOSStub_fb49 {
  strings:
    $key_fb49 = { af 21 [2] db 39 [2] 9c 3b [2] db 2a [2] 95 26 [2] 99 2c [2] 8e 27 [2] 95 69 [2] a8 }

  condition:
    any of them
}