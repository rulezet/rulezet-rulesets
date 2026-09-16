rule TTP_XOR_MULT_DOSStub_fb11 {
  strings:
    $key_fb11 = { af 79 [2] db 61 [2] 9c 63 [2] db 72 [2] 95 7e [2] 99 74 [2] 8e 7f [2] 95 31 [2] a8 }

  condition:
    any of them
}