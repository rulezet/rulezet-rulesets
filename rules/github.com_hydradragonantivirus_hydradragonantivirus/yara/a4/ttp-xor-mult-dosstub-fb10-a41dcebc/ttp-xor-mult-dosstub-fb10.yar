rule TTP_XOR_MULT_DOSStub_fb10 {
  strings:
    $key_fb10 = { af 78 [2] db 60 [2] 9c 62 [2] db 73 [2] 95 7f [2] 99 75 [2] 8e 7e [2] 95 30 [2] a8 }

  condition:
    any of them
}