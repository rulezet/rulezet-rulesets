rule TTP_XOR_MULT_DOSStub_fb61 {
  strings:
    $key_fb61 = { af 09 [2] db 11 [2] 9c 13 [2] db 02 [2] 95 0e [2] 99 04 [2] 8e 0f [2] 95 41 [2] a8 }

  condition:
    any of them
}