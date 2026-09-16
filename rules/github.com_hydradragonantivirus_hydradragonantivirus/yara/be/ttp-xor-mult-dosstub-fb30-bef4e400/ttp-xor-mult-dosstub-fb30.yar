rule TTP_XOR_MULT_DOSStub_fb30 {
  strings:
    $key_fb30 = { af 58 [2] db 40 [2] 9c 42 [2] db 53 [2] 95 5f [2] 99 55 [2] 8e 5e [2] 95 10 [2] a8 }

  condition:
    any of them
}