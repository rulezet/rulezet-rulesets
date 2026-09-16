rule TTP_XOR_MULT_DOSStub_fb60 {
  strings:
    $key_fb60 = { af 08 [2] db 10 [2] 9c 12 [2] db 03 [2] 95 0f [2] 99 05 [2] 8e 0e [2] 95 40 [2] a8 }

  condition:
    any of them
}