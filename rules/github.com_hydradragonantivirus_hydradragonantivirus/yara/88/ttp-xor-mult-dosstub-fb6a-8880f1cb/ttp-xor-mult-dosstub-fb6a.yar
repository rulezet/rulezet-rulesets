rule TTP_XOR_MULT_DOSStub_fb6a {
  strings:
    $key_fb6a = { af 02 [2] db 1a [2] 9c 18 [2] db 09 [2] 95 05 [2] 99 0f [2] 8e 04 [2] 95 4a [2] a8 }

  condition:
    any of them
}