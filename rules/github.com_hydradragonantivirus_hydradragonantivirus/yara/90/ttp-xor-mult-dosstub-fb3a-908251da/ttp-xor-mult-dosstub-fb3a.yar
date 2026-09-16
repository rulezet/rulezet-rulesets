rule TTP_XOR_MULT_DOSStub_fb3a {
  strings:
    $key_fb3a = { af 52 [2] db 4a [2] 9c 48 [2] db 59 [2] 95 55 [2] 99 5f [2] 8e 54 [2] 95 1a [2] a8 }

  condition:
    any of them
}