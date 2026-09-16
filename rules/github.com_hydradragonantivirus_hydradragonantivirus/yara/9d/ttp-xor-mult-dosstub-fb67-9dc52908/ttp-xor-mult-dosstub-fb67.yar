rule TTP_XOR_MULT_DOSStub_fb67 {
  strings:
    $key_fb67 = { af 0f [2] db 17 [2] 9c 15 [2] db 04 [2] 95 08 [2] 99 02 [2] 8e 09 [2] 95 47 [2] a8 }

  condition:
    any of them
}