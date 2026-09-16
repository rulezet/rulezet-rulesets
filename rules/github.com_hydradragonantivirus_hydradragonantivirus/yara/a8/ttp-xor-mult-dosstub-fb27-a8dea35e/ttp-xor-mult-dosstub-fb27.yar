rule TTP_XOR_MULT_DOSStub_fb27 {
  strings:
    $key_fb27 = { af 4f [2] db 57 [2] 9c 55 [2] db 44 [2] 95 48 [2] 99 42 [2] 8e 49 [2] 95 07 [2] a8 }

  condition:
    any of them
}