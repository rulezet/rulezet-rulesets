rule TTP_XOR_MULT_DOSStub_fb75 {
  strings:
    $key_fb75 = { af 1d [2] db 05 [2] 9c 07 [2] db 16 [2] 95 1a [2] 99 10 [2] 8e 1b [2] 95 55 [2] a8 }

  condition:
    any of them
}